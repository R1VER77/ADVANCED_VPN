#!/usr/bin/env python3
"""IPv4/IPv6 output and forwarding guard checks in fresh unprivileged namespaces.

Requires unshare --user --map-root-user --net --mount. Refuses host root or any
inherited interface. No host firewall, routes, services or hardware are changed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from unittest import mock

import avpnctl

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("guard-router", "guard-wan", "guard-client")


def command(*arguments, check=True, input=None):
    """Bound one command wholly inside the isolated test environment."""
    result = subprocess.run(arguments, check=False, input=input, text=True, capture_output=True, timeout=10)
    if check and result.returncode:
        raise RuntimeError(repr(arguments) + ": " + result.stderr)
    return result


def main():
    """Require working positive controls, then reject every guarded escape probe."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    mapping = Path("/proc/self/uid_map").read_text().split()
    if os.geteuid() != 0 or len(mapping) != 3 or mapping[0] != "0" or mapping[1] == "0" or mapping[2] != "1":
        raise RuntimeError("requires a fresh unprivileged user namespace")
    if {link["ifname"] for link in json.loads(command("ip", "-j", "link").stdout)} != {"lo"}:
        raise RuntimeError("requires a fresh network namespace")
    os.umask(0o077)
    args.out.mkdir(parents=True, exist_ok=False)
    command("mount", "--make-rprivate", "/")
    command("mount", "-t", "tmpfs", "tmpfs", "/run")
    results = dict(
        schema=1,
        scope="local_network_namespaces_only",
        phases={},
        input_sha256={
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in ("tools/guard_network_test.py", "tools/avpnctl.py")
        },
    )

    def witnessed(family):
        listing = json.loads(
            command(
                "ip",
                "netns",
                "exec",
                NAMES[1],
                "/usr/sbin/nft",
                "-j",
                "list",
                "chain",
                "inet",
                "guard_witness",
                "input",
            ).stdout
        )
        return sum(
            expression["counter"]["packets"]
            for item in listing["nftables"]
            if item.get("rule", {}).get("comment") == family
            for expression in item["rule"]["expr"]
            if "counter" in expression
        )

    def probes(expected, origins=(NAMES[0], NAMES[2])):
        outcomes = {}
        for origin in origins:
            for family, destination in (("-4", "192.0.2.2"), ("-6", "2001:db8:1::2")):
                before = witnessed(family)
                result = command(
                    "ip", "netns", "exec", origin, "ping", family, "-n", "-c", "1", "-W", "1", destination, check=False
                )
                key = origin + family
                received = witnessed(family) - before
                outcomes[key] = dict(reply=result.returncode == 0, observed_external_requests=received)
                if (result.returncode == 0) != expected or (received > 0) != expected:
                    results["failed_probe"] = dict(origin=origin, family=family, expected=expected, **outcomes[key])
                    raise RuntimeError("guard expectation failed for " + key + ": " + result.stderr)
        for family, address in (("-4", "127.0.0.1"), ("-6", "::1")):
            command("ip", "netns", "exec", NAMES[0], "ping", family, "-n", "-c", "1", "-W", "1", address)
        return outcomes

    try:
        for name in NAMES:
            command("ip", "netns", "add", name)
            command("ip", "-n", name, "link", "set", "lo", "up")
        for first, second, peer, subnet in (("rwan", "w0", NAMES[1], 1), ("rlan", "c0", NAMES[2], 2)):
            command("ip", "link", "add", first, "type", "veth", "peer", "name", second)
            ipv4 = "192.0.2" if subnet == 1 else "198.51.100"
            for device, namespace, host in ((first, NAMES[0], 1), (second, peer, 2)):
                command("ip", "link", "set", device, "netns", namespace)
                command("ip", "-n", namespace, "addr", "add", f"{ipv4}.{host}/24", "dev", device)
                command(
                    "ip", "-n", namespace, "-6", "addr", "add", f"2001:db8:{subnet}::{host}/64", "dev", device, "nodad"
                )
                command("ip", "-n", namespace, "link", "set", device, "up")
            # Keep reachability independent of ND/ARP refresh while OUTPUT is
            # deliberately denied. Otherwise a broken FORWARD policy could look
            # safe merely because its own neighbor solicitation was blocked.
            for device, namespace, remote_device, remote_namespace, remote_host in (
                (first, NAMES[0], second, peer, 2),
                (second, peer, first, NAMES[0], 1),
            ):
                address = json.loads(command("ip", "-n", remote_namespace, "-j", "link", "show", remote_device).stdout)[
                    0
                ]["address"]
                for family, remote in (("-4", f"{ipv4}.{remote_host}"), ("-6", f"2001:db8:{subnet}::{remote_host}")):
                    command(
                        "ip",
                        "-n",
                        namespace,
                        family,
                        "neigh",
                        "replace",
                        remote,
                        "lladdr",
                        address,
                        "nud",
                        "permanent",
                        "dev",
                        device,
                    )
        for family, network, gateway in (
            ("-4", "198.51.100.0/24", "192.0.2.1"),
            ("-6", "2001:db8:2::/64", "2001:db8:1::1"),
        ):
            command("ip", "-n", NAMES[1], family, "route", "add", network, "via", gateway)
        for family, gateway in (("-4", "198.51.100.1"), ("-6", "2001:db8:2::1")):
            command("ip", "-n", NAMES[2], family, "route", "add", "default", "via", gateway)
        command(
            "ip",
            "netns",
            "exec",
            NAMES[0],
            "/usr/sbin/sysctl",
            "-qw",
            "net.ipv4.ip_forward=1",
            "net.ipv6.conf.all.forwarding=1",
        )
        command(
            "ip",
            "netns",
            "exec",
            NAMES[1],
            "/usr/sbin/nft",
            "-f",
            "-",
            input="""table inet guard_witness {
 chain input { type filter hook input priority 0; policy accept;
  ip saddr {192.0.2.1,198.51.100.2} icmp type echo-request counter comment "-4"
  ip6 saddr {2001:db8:1::1,2001:db8:2::2} icmpv6 type echo-request counter comment "-6"
 }
}
""",
        )
        results["phases"]["positive_control"] = probes(True)
        native = ROOT / "target/release/cypherpunk-bootguard"
        policy = command(str(native), "--print-policy").stdout
        results["native_sha256"] = hashlib.sha256(native.read_bytes()).hexdigest()
        command("ip", "netns", "exec", NAMES[0], "/usr/sbin/nft", "-f", "-", input=policy)
        results["phases"]["fallback_guard"] = probes(False)
        replace = avpnctl.replace_table
        with mock.patch.object(avpnctl, "replace_table", side_effect=lambda body: replace(body, NAMES[0])):
            avpnctl.whole_firewall({"network": {"relay_endpoint": "192.0.2.2:41194"}})
        results["phases"]["whole_device_guard_without_tunnel"] = probes(False)
        # A broken variant must leak at the external witness. This catches a
        # false-success test that only lost replies while requests still escaped.
        forward = " chain forward { type filter hook forward priority -100; policy drop;\n }\n"

        def missing_forward(body):
            if body.count(forward) != 1:
                raise RuntimeError("forwarding mutant no longer matches the tested policy")
            replace(body.replace(forward, ""), NAMES[0])

        with mock.patch.object(avpnctl, "replace_table", side_effect=missing_forward):
            avpnctl.whole_firewall({"network": {"relay_endpoint": "192.0.2.2:41194"}})
        results["phases"]["broken_forwarding_policy_detected"] = probes(True, (NAMES[2],))
        with mock.patch.object(avpnctl, "replace_table", side_effect=lambda body: replace(body, NAMES[0])):
            avpnctl.whole_firewall({"network": {"relay_endpoint": "192.0.2.2:41194"}})
        results["phases"]["whole_device_guard_restored"] = probes(False)
        command("ip", "netns", "exec", NAMES[0], "/usr/sbin/nft", "delete", "table", "inet", "advanced_vpn")
        results["phases"]["positive_control_after_removal"] = probes(True)
        results["status"] = "passed"
    except BaseException:
        results["status"] = "failed"
        raise
    finally:
        (args.out / "RESULT.json").write_text(json.dumps(results, indent=2) + "\n")
        for name in reversed(NAMES):
            command("ip", "netns", "delete", name, check=False)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
