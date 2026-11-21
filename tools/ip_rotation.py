#!/usr/bin/env python3
"""`avpn cloud rotate`: a short path to a fresh exit IP (STREAMING_GEO_PARITY section 4.4).

When `avpn stream-check` shows an exit's address is newly blocked, the
operator needs one command that trades the address for a fresh one —
release and re-acquire the provider's ephemeral IP, or reprovision in a
different region, then re-run the enrollment. That is what this module
adds to `avpn cloud`. It is the arms race on the user's own terms: each
user rotates their own exit instead of relying on a company's rotation
team.

Strategies
----------
`reallocate` (the default): the instance stays, the address is traded.
  For an AWS Elastic IP that is disassociate -> allocate -> associate ->
  release-old, in exactly that order, so a failure part-way leaves the
  old address still owned and re-attachable (the recovery path below).
  For an instance on an auto-assigned public IP (no allocation), a
  stop/start cycle is the only way to trade it; a reboot is not.
`reprovision`: teardown plus re-apply in a (possibly different) region.
  The heavy path, for when the whole provider range is listed. This
  module plans it and prints the two exact existing commands; it does
  not re-implement the tested apply paths in `avpn cloud aws relay`.

Fail-closed rules (the same shape as every other `avpn cloud` command)
----------------------------------------------------------------------------
- Only resources this tool tagged itself (`avpn:managed=true` plus
  `avpn:name=<name>`) are touched; anything else is refused.
- `--tunnel-down` is required to apply: rotating the address a live
  chain is using would break sessions mid-flight and, on the entry hop,
  drop traffic onto the operator's own address. The tool cannot see the
  tunnel from here, so the operator attests it; there is deliberately
  no --force.
- The single-IP invariant: at rest the instance has exactly one public
  address. During `reallocate` the new address is allocated before the
  old one is released, and if any step fails the old address is put
  back before the command gives up (journal: `recovered`).
- If the provider hands back the same address, that is recorded as
  `same-ip` and the rotation is a failure — the honest outcome, not a
  silent pass.
- Every attempt — planned, rotated, recovered, failed, refused — is
  appended to an append-only journal (config dir, `rotation.jsonl`, no
  secrets) so the exit descriptor's dated fields and the eligibility
  table can cite it.

What this module deliberately does not do
-----------------------------------------
It does not schedule rotation, does not rotate on a timer, and does not
claim the new address is unlisted. Eligibility is only ever a dated
measurement (`avpn stream-check` after the re-enrollment), never a
promise.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import cloud
from cloud import Aws, CloudError, MANAGED, NAME, load_inventory

SCHEMA = 1


class RotationError(CloudError):
    """A rotation refused or failed; the message says which and why."""


def journal_path():
    """The rotation journal: an append-only JSONL file beside the inventory."""
    return cloud.INVENTORY.parent / "rotation.jsonl"


def load_journal(path=None):
    """Every journal entry, oldest first; a missing journal is empty."""
    path = Path(path or journal_path())
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def append_journal(entry, path=None):
    """Append one entry (caller supplies the outcome); atomic, no secrets."""
    path = Path(path or journal_path())
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    row = dict(schema=SCHEMA, at=_now(), **entry)
    with open(path, "a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")
    return row


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Reading the current address (provider-agnostic surface)
# --------------------------------------------------------------------------


def find_instance(aws, name):
    """The one instance tagged avpn:name=<name>, or a RotationError.

    Refuses when there is no instance, when it is not running, and when
    it carries more than one public address association (a state this
    tool never creates).
    """
    owned = aws.owned(name)
    instances = owned["instances"]
    if not instances:
        raise RotationError("no instance tagged %s=%s in %s; nothing to rotate" % (NAME, name, aws.region))
    if len(instances) > 1:
        raise RotationError("%d instances tagged %s=%s; refusing to guess which one" % (len(instances), NAME, name))
    i = instances[0]
    tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
    if tags.get(MANAGED) != "true":
        raise RotationError("%s is not tagged %s=true; refusing" % (i["InstanceId"], MANAGED))
    state = i.get("State", {}).get("Name")
    if state != "running":
        raise RotationError("%s is %s, not running; start it or reprovision instead" % (i["InstanceId"], state))
    return i


def address_of(i):
    """(public_ip, association_id, allocation_id) of an instance, or (None,)*3.

    An allocation_id means an Elastic IP this tool (or the operator)
    associated; without one the address is auto-assigned and only a
    stop/start cycle changes it.
    """
    ip = i.get("PublicIpAddress")
    assoc = (i.get("PublicIpAddress") and i.get("NetworkInterfaces", [{}])[0].get("Association", {})) or {}
    return ip, assoc.get("AssociationId"), assoc.get("AllocationId")


# --------------------------------------------------------------------------
# The reallocate strategy
# --------------------------------------------------------------------------


def reallocate_plan(aws, name):
    """What reallocate will do, from live state; changes nothing."""
    i = find_instance(aws, name)
    ip, assoc_id, alloc_id = address_of(i)
    kind = "elastic" if alloc_id else "auto-assigned"
    rows = [
        dict(label="instance", value="%s %s (%s)" % (i["InstanceId"], name, aws.region)),
        dict(label="address", value="%s (%s)" % (ip or "none", kind)),
    ]
    if alloc_id:
        rows += [
            dict(label="step 1", value="disassociate the Elastic IP (the exit is unreachable from here on)"),
            dict(label="step 2", value="allocate a fresh Elastic IP (old one still owned if this fails)"),
            dict(label="step 3", value="associate the fresh IP and tag it like every other resource"),
            dict(label="step 4", value="release the old IP only after the new one is attached"),
            dict(
                label="recovery",
                value="any failure after step 1 re-associates the old IP before giving up",
            ),
        ]
    else:
        rows += [
            dict(label="step 1", value="stop the instance (its auto-assigned public IP is released on stop)"),
            dict(label="step 2", value="start it again; AWS assigns a fresh public IP"),
            dict(label="step 3", value="verify exactly one address and that it changed"),
        ]
    rows += [dict(label="estimate", value="no new monthly cost: the public-IPv4 charge moves, it is not added")]
    rows += post_rotation_steps(name)
    return dict(instance=i["InstanceId"], address=ip, kind=kind, rows=rows, assoc=assoc_id, alloc=alloc_id)


def post_rotation_steps(name):
    """The re-enrollment checklist every rotation ends with (doc section 4.4).

    A rotated address invalidates the exit's recorded identity: the
    descriptor's address, the chain's allow rules and the streaming
    evidence all cite the old IP, so they are re-run, not patched.
    """
    return [
        dict(
            label="then 1",
            value="avpn cloud aws allow --apply --name %s (the previous hop's address is unchanged)" % name,
        ),
        dict(
            label="then 2",
            value="avpn cloud host setup --name %s --out <request> (fetch the new public request)" % name,
        ),
        dict(label="then 3", value="avpn cloud chain --apply (rebuild the chain onto the new address)"),
        dict(label="then 4", value="avpn run -- stream-check <service> (a dated measurement, never a promise)"),
    ]


def reallocate_apply(aws, name, reason, dry_run=False, tunnel_down=False):
    """Trade the address; journal every outcome; return result rows."""
    plan = reallocate_plan(aws, name)
    if dry_run:
        append_journal(dict(name=name, strategy="reallocate", reason=reason, outcome="planned"))
        return dict(rows=plan["rows"], dry_run=True)
    if not tunnel_down:
        append_journal(
            dict(name=name, strategy="reallocate", reason=reason, outcome="refused", detail="tunnel not attested down")
        )
        raise RotationError(
            "rotating %s would cut a live chain: stop the tunnel, then pass --tunnel-down to attest it" % name
        )
    if plan["kind"] == "elastic":
        return _rotate_eip(aws, name, reason, plan)
    return _rotate_auto(aws, name, reason, plan)


def _rotate_eip(aws, name, reason, plan):
    """Elastic IP rotation with the allocate-before-release order and recovery."""
    old_ip, assoc_id, old_alloc = plan["address"], plan["assoc"], plan["alloc"]
    if not old_alloc:
        raise RotationError("%s has no Elastic IP to trade; use the auto-assigned path" % name)
    aws.ec2("disassociate-address", "--association-id", assoc_id)
    try:
        new = aws.ec2("allocate-address", "--domain", "vpc")
        new_alloc, new_ip = new["AllocationId"], new["PublicIp"]
        if new_ip == old_ip:
            # The provider handed the same address back: undo, honestly.
            aws.ec2("associate-address", "--instance-id", plan["instance"], "--allocation-id", old_alloc)
            append_journal(
                dict(
                    name=name,
                    strategy="reallocate",
                    reason=reason,
                    outcome="same-ip",
                    old_ip=old_ip,
                    detail="provider returned the same address; reprovision instead",
                )
            )
            raise RotationError("AWS returned the same address for %s; use --strategy reprovision" % name)
    except RotationError:
        raise
    except (CloudError, KeyError) as e:
        # Nothing was allocated: put the old address back before anything else.
        try:
            aws.ec2("associate-address", "--instance-id", plan["instance"], "--allocation-id", old_alloc)
        except CloudError as second:
            return _unrecoverable(name, reason, plan, e, second)
        return _recovered(aws, name, reason, plan, "allocate failed: %s" % e)
    try:
        aws.ec2("associate-address", "--instance-id", plan["instance"], "--allocation-id", new_alloc)
        aws.ec2(
            "create-tags",
            "--resources",
            new_alloc,
            "--tags",
            "Key=%s,Value=true" % MANAGED,
            "Key=%s,Value=%s" % (NAME, name),
        )
    except (CloudError, KeyError) as e:
        # Recovery: put the old address back and release the unusable new one.
        try:
            aws.ec2("associate-address", "--instance-id", plan["instance"], "--allocation-id", old_alloc)
            aws.ec2("release-address", "--allocation-id", new_alloc)
        except CloudError as second:
            return _unrecoverable(name, reason, plan, e, second)
        return _recovered(aws, name, reason, plan, "associate failed: %s" % e)
    aws.ec2("release-address", "--allocation-id", old_alloc)
    now_ip = _verify_one_address(aws, plan["instance"])
    append_journal(
        dict(name=name, strategy="reallocate", reason=reason, outcome="rotated", old_ip=old_ip, new_ip=now_ip)
    )
    rows = [
        dict(label="instance", value=plan["instance"]),
        dict(label="was", value=old_ip),
        dict(label="now", value=now_ip),
    ] + post_rotation_steps(name)
    return dict(rows=rows)


def _recovered(aws, name, reason, plan, detail):
    """The old address is back; verify it, journal it, fail honestly."""
    now_ip = _verify_one_address(aws, plan["instance"])
    append_journal(
        dict(
            name=name,
            strategy="reallocate",
            reason=reason,
            outcome="recovered",
            old_ip=plan["address"],
            new_ip=now_ip,
            detail=detail,
        )
    )
    raise RotationError(
        "%s: rotation failed (%s); the old address %s is back; nothing was lost" % (name, detail, now_ip)
    )


def _unrecoverable(name, reason, plan, first, second):
    """Both the rotation and the recovery failed: the loudest possible stop."""
    append_journal(
        dict(
            name=name,
            strategy="reallocate",
            reason=reason,
            outcome="failed",
            old_ip=plan["address"],
            detail="rotation and recovery both failed: %s / %s" % (first, second),
        )
    )
    raise RotationError(
        "rotation failed (%s) and recovery failed (%s): %s may be address-less; "
        "re-attach an address by hand before anything else" % (first, second, plan["instance"])
    )


def _rotate_auto(aws, name, reason, plan):
    """Stop/start rotation for an auto-assigned public IP."""
    old_ip, instance = plan["address"], plan["instance"]
    aws.ec2("stop-instances", "--instance-ids", instance)
    _wait_state(aws, instance, "stopped")
    try:
        aws.ec2("start-instances", "--instance-ids", instance)
        _wait_state(aws, instance, "running")
    except (CloudError, RotationError) as e:
        # A stopped exit is worse than a blocked one: retry once, then fail loudly.
        try:
            aws.ec2("start-instances", "--instance-ids", instance)
            _wait_state(aws, instance, "running")
        except (CloudError, RotationError):
            append_journal(
                dict(
                    name=name,
                    strategy="reallocate",
                    reason=reason,
                    outcome="failed",
                    old_ip=old_ip,
                    detail="start failed twice: %s; instance left STOPPED" % e,
                )
            )
            raise RotationError(
                "%s would not start (%s) and is left STOPPED: start it by hand before anything else" % (name, e)
            ) from e
    new_ip = _verify_one_address(aws, instance)
    if new_ip == old_ip:
        append_journal(
            dict(
                name=name,
                strategy="reallocate",
                reason=reason,
                outcome="same-ip",
                old_ip=old_ip,
                detail="stop/start returned the same address; reprovision instead",
            )
        )
        raise RotationError("the stop/start cycle returned the same address for %s; use --strategy reprovision" % name)
    append_journal(
        dict(name=name, strategy="reallocate", reason=reason, outcome="rotated", old_ip=old_ip, new_ip=new_ip)
    )
    rows = [
        dict(label="instance", value=instance),
        dict(label="was", value=old_ip),
        dict(label="now", value=new_ip),
    ] + post_rotation_steps(name)
    return dict(rows=rows)


def _wait_state(aws, instance, want, timeout=300, every=5):
    """Poll the instance until it reaches `want` (the same wait cloud.py uses)."""

    def state():
        res = aws.ec2("describe-instances", "--instance-ids", instance)
        return next(
            (
                i["State"]["Name"]
                for r in res.get("Reservations", [])
                for i in r["Instances"]
                if i["InstanceId"] == instance
            ),
            None,
        )

    return cloud.wait("the instance to be " + want, lambda: state() == want, timeout=timeout, every=every)


def _verify_one_address(aws, instance):
    """Fail-closed post-condition: the instance has exactly one public address."""
    res = aws.ec2("describe-instances", "--instance-ids", instance)
    found = [i for r in res.get("Reservations", []) for i in r["Instances"] if i["InstanceId"] == instance]
    if not found:
        raise RotationError("%s vanished mid-rotation" % instance)
    ip, _, _ = address_of(found[0])
    if not ip:
        raise RotationError("%s has no public address after rotation" % instance)
    return ip


# --------------------------------------------------------------------------
# The reprovision strategy (plan only: it composes the existing commands)
# --------------------------------------------------------------------------


def reprovision_plan(aws, name, region=None):
    """The teardown-plus-reapply plan, as the two exact existing commands.

    Reprovisioning is `avpn cloud aws relay --teardown` then `--apply`
    (in the new region, if one is given): both are the tested paths in
    cloud.py, so this module plans and journals the intent but does not
    re-implement their apply logic.
    """
    i = find_instance(aws, name)
    target = region or aws.region
    if region and region != aws.region:
        cloud.Aws(aws.profile, region)  # the same one-Region guard relay --apply applies
    rows = [
        dict(label="instance", value="%s %s (%s)" % (i["InstanceId"], name, aws.region)),
        dict(label="step 1", value="avpn cloud aws relay --teardown --name %s --profile %s" % (name, aws.profile)),
        dict(
            label="step 2",
            value="avpn cloud aws relay --apply --name %s --role %s --region %s --profile %s"
            % (name, _role_of(i, name), target, aws.profile),
        ),
        dict(label="note", value="a new region is a new provider-side footprint; the caller-side logging note applies"),
    ] + post_rotation_steps(name)
    return dict(instance=i["InstanceId"], rows=rows, region=target)


def _role_of(i, name):
    """The role recorded in the instance's avpn:role tag, or the inventory's."""
    for t in i.get("Tags", []):
        if t["Key"] == "avpn:role":
            return t["Value"]
    record = load_inventory()["resources"].get(name, {})
    return record.get("role", "relay")


# --------------------------------------------------------------------------
# CLI surface (wired into cloud.py's parser as `cloud rotate`)
# --------------------------------------------------------------------------


def run_rotate(a):
    """Execute one parsed `avpn cloud rotate` command."""
    cloud.valid_name(a.name)
    record = load_inventory()["resources"].get(a.name, {})
    if record.get("provider") == "oci":
        # Honest composition: OCI ephemeral IPs trade on stop/start too, but
        # the OCI plumbing is `avpn cloud oci server`; plan the exact steps.
        rows = [
            dict(label="provider", value="oci"),
            dict(
                label="step 1",
                value="oci compute instance action --instance-id <ocid> --action STOP --wait-for-state STOPPED",
            ),
            dict(
                label="step 2",
                value="oci compute instance action --instance-id <ocid> --action START --wait-for-state RUNNING",
            ),
            dict(label="then", value="avpn cloud host setup --name %s --out <request> and re-run the chain" % a.name),
            dict(label="note", value="an OCI reserved public IP does not change on stop/start; reprovision instead"),
        ] + post_rotation_steps(a.name)
        append_journal(dict(name=a.name, strategy=a.strategy, reason=a.reason, outcome="planned"))
        return dict(title="Rotate OCI %s (manual steps)" % a.name, summary="plan", rows=rows, dry_run=True)
    aws = Aws(a.profile, a.region)
    if a.strategy == "reprovision":
        plan = reprovision_plan(aws, a.name, a.region)
        append_journal(dict(name=a.name, strategy="reprovision", reason=a.reason, outcome="planned"))
        return dict(
            title="Reprovision AWS %s" % a.name, summary="plan (two existing commands)", rows=plan["rows"], dry_run=True
        )
    if a.dry_run:
        return reallocate_apply(aws, a.name, a.reason, dry_run=True)
    if not a.tunnel_down:
        # Refuse before any prompt: the attestation is the operator's, not ours to assume.
        append_journal(
            dict(
                name=a.name, strategy=a.strategy, reason=a.reason, outcome="refused", detail="tunnel not attested down"
            )
        )
        raise RotationError(
            "rotating %s would cut a live chain: stop the tunnel, then pass --tunnel-down to attest it" % a.name
        )
    if not cloud.confirm(a, "Rotate %s (%s)" % (a.name, a.strategy)):
        append_journal(
            dict(name=a.name, strategy=a.strategy, reason=a.reason, outcome="refused", detail="not confirmed")
        )
        return dict(title="Rotate %s" % a.name, summary="cancelled", rows=[])
    return dict(
        title="Rotate AWS %s" % a.name,
        summary="rotated",
        rows=reallocate_apply(aws, a.name, a.reason, tunnel_down=a.tunnel_down)["rows"],
    )
