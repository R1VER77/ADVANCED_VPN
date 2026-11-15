"""wf_real.py's busy-CPU setup: what is pinned where, and what each run records.

The real-website re-run compares today's `fast` with the wire clock while the browser
competes with the client's data plane for the same cores; these tests pin down that the
browser and the client are placed together and the servers and capture elsewhere.
"""

import inspect
import unittest

import wf_real


class PinningTests(unittest.TestCase):
    def test_cores_are_applied_with_taskset_or_not_at_all(self):
        self.assertEqual(wf_real.pinned("0,1", ["python", "x"]), ["/usr/bin/taskset", "-c", "0,1", "python", "x"])
        self.assertEqual(wf_real.pinned("", ["python", "x"]), ["python", "x"])

    def test_the_browser_and_client_share_cores_and_the_servers_and_capture_do_not(self):
        src = inspect.getsource(wf_real.worker)
        # The client's controller (and so its data plane) on the client cores, the others not.
        self.assertIn('cpus = a.client_cpus if role == "client" else a.server_cpus', src)
        # Every page load (browser and driver) on the client cores.
        self.assertIn("pinned(a.client_cpus, run + list(argv))", src)
        # The capture never competes with the browser.
        self.assertIn("subprocess.Popen(pinned(a.server_cpus, sniff))", src)

    def test_the_wire_clock_gets_fq_and_its_counters_are_kept(self):
        src = inspect.getsource(wf_real.worker)
        self.assertIn('"qdisc", "replace", "dev", capture_dev, "root", "fq"', src)
        self.assertIn('"clock.json"', src)

    def test_each_run_records_the_hosts_power_state(self):
        power = wf_real.host_power()
        self.assertEqual(set(power), {"on_mains", "governor"})


if __name__ == "__main__":
    unittest.main()
