"""Release gate: publish a tag only when EVERY verify run on its commit passed.

A tag push and its branch push each start a `verify` run on the same commit. Accepting
any one success let v0.10.0 ship although its tag run had failed on a real (if
intermittent) bug. Here:
- the tag's own verify run must exist and pass (so the gate cannot decide before it
  has even registered);
- every other verify run on the commit must finish, and none may fail. A cancelled run
  does not block: verify cancels an older run on the same ref when a newer commit
  lands, which says nothing about this commit. A re-run that passes counts (GitHub
  reports a run's latest attempt).

Usage (in release.yml): python3 tools/release_gate.py REPO SHA TAG
Standard library only; needs the `gh` CLI with GH_TOKEN."""

import json
import os
import shutil
import subprocess
import sys
import time

OK = {"success"}
NOT_BLOCKING = {"success", "cancelled", "skipped"}


def decide(runs, tag):
    """('wait' | 'pass' | 'fail', message, url) for the verify runs on one commit."""
    tag_runs = [r for r in runs if r.get("headBranch") == tag and r.get("event") == "push"]
    if not tag_runs:
        return "wait", "the tag's own verify run has not started", None
    pending = [r for r in runs if r.get("status") != "completed"]
    if pending:
        return "wait", "%d verify run(s) still running" % len(pending), None
    blocking = [r for r in runs if r.get("conclusion") not in NOT_BLOCKING]
    if blocking:
        return (
            "fail",
            "verify failed: "
            + ", ".join("%s (%s) %s" % (r.get("url"), r.get("headBranch"), r.get("conclusion")) for r in blocking),
            None,
        )
    passed = [r for r in tag_runs if r.get("conclusion") in OK]
    if not passed:
        return "fail", "the tag's own verify run did not pass (cancelled)", None
    return "pass", "all %d verify run(s) passed" % len(runs), passed[0].get("url")


def runs_for(repo, sha):
    """Every verify run GitHub has recorded for `sha` (latest attempt of each)."""
    gh = shutil.which("gh")
    if not gh:
        raise ValueError("the gh CLI is not installed")
    out = subprocess.run(
        [gh, "run", "list", "-R", repo, "--workflow", "verify.yml", "--commit", sha, "--limit", "50",
         "--json", "databaseId,status,conclusion,headBranch,event,url"],
        capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip
    return json.loads(out)


def main(repo, sha, tag, attempts=120, pause=30):
    """Poll until the verdict is final; 0 releases, 1 refuses. Records VERIFY_URL."""
    message = "not checked"
    for _ in range(attempts):
        try:
            verdict, message, url = decide(runs_for(repo, sha), tag)
        except (subprocess.CalledProcessError, ValueError) as e:
            verdict, message, url = "wait", "gh failed: %s" % e, None
        print(message, flush=True)
        if verdict == "pass":
            env = os.environ.get("GITHUB_ENV")
            if env:
                with open(env, "a") as f:
                    f.write("VERIFY_URL=%s\n" % url)
            return 0
        if verdict == "fail":
            return 1
        time.sleep(pause)
    print("verify did not finish for %s: %s" % (sha, message))
    return 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
