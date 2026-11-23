#!/usr/bin/env python3
"""The local assistant: explains a troubleshooting finding in plain words, offline.

    assistant.py explain < finding.json     one JSON reply: explanation, suggestion, source

The finding comes from tools/troubleshoot.py, which alone decides the cause and the
fixes. The model (Gemma 3 1B, from the cypherpunk-vpn-assistant package) only writes the
explanation, and may name one of the finding's own fixes as a suggestion. Its answer is
held to a JSON schema and checked again here:
- a suggestion outside the finding's fixes is dropped;
- an explanation that reads like a command is refused.

Isolation:
- the model server runs in its own network namespace (`unshare -rn`: no interface but
  loopback), with `--offline`, reached only through a Unix socket in a private directory;
- it is stopped after each answer;
- it is given the finding's scrubbed evidence, never the raw log, a PIN or a credential.

When the package is missing, the namespace is refused, or the model fails, the reply is
the finding's own text (source "rules"): the troubleshooting never depends on the model.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

import troubleshoot  # noqa: E402

SCHEMA = 1
HOME = Path("/usr/lib/cypherpunk-vpn/assistant")
MODEL = HOME / "gemma-3-1b-it-Q8_0.gguf"
SERVER = HOME / "llama-server"
MODEL_SHA256 = "616dfb049ad14288d971d96f5ca4953fdebbf1e3cd407ad159f3bfd47090201d"
MAX_EXPLANATION = 600
START_TIMEOUT = 90
ANSWER_TIMEOUT = 120
FIX_TEXT = {
    "retry_build": "build the route again (setup now waits for a busy server and recovers it)",
    "sign_in_aws": "sign in to AWS again for this server's profile",
    "host_update": "run this server's update step on its own (one PIN and touch)",
    "unlock_server": "unlock the server's keys with the security key",
    "check_health": "check every server's state (stopped, locked, capped or gone)",
    "open_docs": "open the troubleshooting guide",
}
# An explanation is prose. These look like instructions to run something, which the model
# must never give: actions come only from the finding's typed fixes.
COMMANDISH = re.compile(r"`|\bsudo\b|\$\s|\brm\s+-|\bcurl\b|\bwget\b|&&|\|\s*sh\b|https?://|\bchmod\b|\bsystemctl\b")
SYSTEM = (
    "You explain why a step of a VPN route setup failed, for a person who is not an "
    "expert. Write two or three short, plain sentences using only the facts given. Do not "
    "give commands, file paths, links or steps to type. Then name the one fix from the "
    "allowed list that best matches the facts."
)


def prompt(finding):
    """The user message: the finding's facts and its allowed fixes, nothing else."""
    lines = ["Step that failed: " + (finding.get("step") or "the route build"),
             "Finding: " + finding["title"] + ". " + finding["meaning"], "Evidence from the build:"]  # fmt: skip
    lines += ["- " + e for e in finding["evidence"]] or ["- (no output line matched)"]
    lines.append("Allowed fixes:")
    lines += ["- %s: %s" % (f["action"], FIX_TEXT[f["action"]]) for f in finding["fixes"]]
    return "\n".join(lines)


def answer_schema(finding):
    """The JSON schema the model's output is held to."""
    actions = sorted({f["action"] for f in finding["fixes"]}) or ["open_docs"]
    return {"type": "object", "additionalProperties": False, "required": ["explanation", "suggestion"],
            "properties": {"explanation": {"type": "string", "maxLength": MAX_EXPLANATION},
                           "suggestion": {"type": "string", "enum": actions}}}  # fmt: skip


def rules_reply(finding, why="assistant_not_installed"):
    """The answer without a model: the finding's own words."""
    return dict(schema=SCHEMA, source="rules", why=why, explanation=finding["meaning"], suggestion=None)


def check(finding, text):
    """The model's raw answer, validated; None when it cannot be used."""
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("explanation"), str):
        return None
    explanation = " ".join(value["explanation"].split())[:MAX_EXPLANATION]
    if not explanation or COMMANDISH.search(explanation):
        return None
    suggestion = None
    for f in finding["fixes"]:
        if f["action"] == value.get("suggestion"):
            suggestion = f
            break
    return dict(schema=SCHEMA, source="assistant", explanation=explanation, suggestion=suggestion)


def explain(finding, ask=None):
    """Explain a finding: the model's validated words, or the rules' own text."""
    ask = ask or ask_local_model
    try:
        text = ask(prompt(finding), answer_schema(finding))
    except AssistantUnavailable as e:
        return rules_reply(finding, str(e))
    checked = check(finding, text)
    return checked or rules_reply(finding, "answer_refused")


class AssistantUnavailable(Exception):
    """No model to ask: a fixed reason, shown as such."""


def installed(model=MODEL, server=SERVER):
    """The packaged model and server, present and the model exactly the pinned file."""
    if not (model.is_file() and server.is_file() and os.access(server, os.X_OK)):
        raise AssistantUnavailable("assistant_not_installed")
    marker = model.with_name(model.name + ".sha256")
    if not marker.is_file() or marker.read_text().split()[0] != MODEL_SHA256:
        raise AssistantUnavailable("model_not_verified")


def exchange(path, raw, timeout):
    """Send one raw HTTP request over the Unix socket; (status line, headers, body)."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(path))
        s.sendall(raw)
        reply = b""
        while chunk := s.recv(65536):
            reply += chunk
            if len(reply) > 1 << 20:
                raise AssistantUnavailable("answer_too_large")
    head, _, payload = reply.partition(b"\r\n\r\n")
    if b"transfer-encoding: chunked" in head.lower():
        out, rest = b"", payload
        while rest:
            size, _, rest = rest.partition(b"\r\n")
            n = int(size.split(b";")[0] or b"0", 16)
            if n == 0:
                break
            out, rest = out + rest[:n], rest[n + 2 :]
        payload = out
    return head.split(b"\r\n", 1)[0], payload


def ready(path):
    """The model is loaded: /health answers 200 (it answers 503 while loading)."""
    status, _ = exchange(path, b"GET /health HTTP/1.1\r\nHost: assistant\r\nConnection: close\r\n\r\n", 5)
    return b" 200 " in status + b" "


def request(path, body, timeout):
    """Ask the loaded model once; its answer's text."""
    data = json.dumps(body).encode()
    raw = (b"POST /v1/chat/completions HTTP/1.1\r\nHost: assistant\r\nContent-Type: application/json\r\n"
           b"Connection: close\r\nContent-Length: %d\r\n\r\n" % len(data) + data)  # fmt: skip
    status, payload = exchange(path, raw, timeout)
    if b" 200 " not in status + b" ":
        raise AssistantUnavailable("model_error")
    return json.loads(payload)["choices"][0]["message"]["content"]


def ask_local_model(user, schema, model=MODEL, server=SERVER, threads=None):
    """Start the model server with no network, ask once, stop it."""
    installed(model, server)
    unshare = shutil.which("unshare")
    if not unshare:
        raise AssistantUnavailable("no_network_isolation")
    with tempfile.TemporaryDirectory(prefix="cpvpn-assistant-") as tmp:
        os.chmod(tmp, 0o700)
        sock = Path(tmp) / "model.sock"
        argv = [unshare, "-rn", "--", str(server), "-m", str(model), "--host", str(sock), "--offline",
                "-c", "4096", "-t", str(threads or max(1, (os.cpu_count() or 2) // 2)), "--log-disable"]  # fmt: skip
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + START_TIMEOUT
            while not sock.exists():
                if proc.poll() is not None:
                    err = (proc.stderr.read() or b"").decode(errors="replace")
                    raise AssistantUnavailable("no_network_isolation" if "unshare" in err else "model_did_not_start")
                if time.monotonic() > deadline:
                    raise AssistantUnavailable("model_did_not_start")
                time.sleep(0.2)
            body = dict(messages=[dict(role="system", content=SYSTEM), dict(role="user", content=user)],
                        temperature=0.2, max_tokens=260,
                        response_format=dict(type="json_schema", json_schema=dict(name="answer", schema=schema)))  # fmt: skip
            while True:
                try:
                    if ready(sock):
                        break
                except OSError:
                    pass  # the socket exists before the server accepts on it
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise AssistantUnavailable("model_did_not_start")
                time.sleep(0.5)
            try:
                return request(sock, body, ANSWER_TIMEOUT)
            except (OSError, ValueError, KeyError, IndexError):
                raise AssistantUnavailable("model_error") from None
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            proc.stderr.close()


def main(argv=None):
    """Explain a finding read from stdin; one JSON reply."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_subparsers(dest="command", required=True).add_parser("explain")
    parser.parse_args(argv)
    finding = json.loads(sys.stdin.read(64 * 1024))
    if finding.get("schema") != SCHEMA or not isinstance(finding.get("fixes"), list):
        print(json.dumps(dict(schema=SCHEMA, error="invalid_finding")))
        return 1
    finding["fixes"] = [f for f in finding["fixes"] if isinstance(f, dict) and f.get("action") in troubleshoot.ACTIONS]
    print(json.dumps(explain(finding)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
