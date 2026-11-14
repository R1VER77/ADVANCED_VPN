"""The release gate publishes only when every verify run on the commit passed."""

import unittest

from release_gate import decide

TAG = "v1.2.3"


def run(branch, status="completed", conclusion="success", event="push"):
    return dict(headBranch=branch, status=status, conclusion=conclusion, event=event, url="u/" + branch)


class ReleaseGateTests(unittest.TestCase):
    def test_both_runs_passed_releases(self):
        verdict, _, url = decide([run("main"), run(TAG)], TAG)
        self.assertEqual((verdict, url), ("pass", "u/" + TAG))

    def test_the_v0_10_0_case_is_refused(self):
        # main passed, the tag's own run failed: any-success used to release this.
        self.assertEqual(decide([run("main"), run(TAG, conclusion="failure")], TAG)[0], "fail")

    def test_a_failed_branch_run_also_blocks(self):
        self.assertEqual(decide([run("main", conclusion="failure"), run(TAG)], TAG)[0], "fail")

    def test_timeouts_and_startup_failures_block(self):
        for c in ["timed_out", "startup_failure", "action_required", None]:
            self.assertEqual(decide([run(TAG), run("main", conclusion=c)], TAG)[0], "fail", c)

    def test_waits_until_the_tag_run_exists(self):
        # Only main's run is visible yet: never decide on it alone.
        self.assertEqual(decide([run("main")], TAG)[0], "wait")
        self.assertEqual(decide([], TAG)[0], "wait")

    def test_waits_while_any_run_is_still_going(self):
        self.assertEqual(decide([run(TAG), run("main", status="in_progress", conclusion="")], TAG)[0], "wait")

    def test_a_cancelled_branch_run_does_not_block(self):
        # verify cancels an older run on main when a newer commit lands.
        self.assertEqual(decide([run("main", conclusion="cancelled"), run(TAG)], TAG)[0], "pass")

    def test_a_cancelled_tag_run_is_not_a_pass(self):
        self.assertEqual(decide([run("main"), run(TAG, conclusion="cancelled")], TAG)[0], "fail")

    def test_a_pull_request_run_on_the_same_commit_counts(self):
        self.assertEqual(decide([run(TAG), run("feature", conclusion="failure", event="pull_request")], TAG)[0], "fail")


if __name__ == "__main__":
    unittest.main()
