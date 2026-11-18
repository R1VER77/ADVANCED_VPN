"""wf_real.py's busy-CPU setup: what is pinned where, and what each run records.

The real-website re-run compares today's `fast` with the wire clock while the browser
competes with the client's data plane for the same cores; these tests pin down that the
browser and the client are placed together and the servers and capture elsewhere.
"""

import inspect
import unittest

import wf_real


class PinningTests(unittest.TestCase):
    def test_observed_workers_enter_namespaces_without_a_python_preexec_hook(self):
        from unittest import mock

        with mock.patch.object(wf_real.subprocess, "Popen") as spawn:
            wf_real.in_netns("cli", ["/usr/bin/true"], start_new_session=True)
        spawn.assert_called_once_with(
            ["/usr/bin/nsenter", "--net=/run/netns/cli", "--", "/usr/bin/true"], start_new_session=True
        )

    def test_a_failed_worker_cannot_be_reported_as_a_successful_collection(self):
        from types import SimpleNamespace

        waited = []

        def worker(code):
            def wait():
                waited.append(code)
                return code

            return SimpleNamespace(wait=wait)

        wf_real.wait_workers([worker(0)])
        with self.assertRaisesRegex(ValueError, "at least one worker"):
            wf_real.wait_workers([])
        with self.assertRaisesRegex(RuntimeError, "2 collection workers failed"):
            wf_real.wait_workers([worker(1), worker(0), worker(-9)])
        self.assertEqual(waited, [0, 1, 0, -9])

    def test_load_order_is_reproducible_but_can_vary_between_rounds(self):
        import random

        sites = dict(monitored=[f"s{i}.test" for i in range(10)], loads=2, open_world=["u.test"])
        legacy = [(s, i) for i, s in enumerate(sites["monitored"]) for _ in range(2)] + [("u.test", -1)]
        random.Random(7).shuffle(legacy)  # noqa: S311  (reproduce the original experiment order)
        self.assertEqual(wf_real.collection_plan(sites), legacy)
        changed = wf_real.collection_plan(sites, 8)
        self.assertNotEqual(changed, legacy)
        self.assertCountEqual(changed, legacy)
        self.assertEqual(changed, wf_real.collection_plan(sites, 8))
        self.assertIn('"--seed", str(a.seed)', inspect.getsource(wf_real.collect))
        self.assertIn("load_order_seed=a.seed", inspect.getsource(wf_real.worker))

    def test_cores_are_applied_with_taskset_or_not_at_all(self):
        self.assertEqual(wf_real.pinned("0,1", ["python", "x"]), ["/usr/bin/taskset", "-c", "0,1", "python", "x"])
        self.assertEqual(wf_real.pinned("", ["python", "x"]), ["python", "x"])

    def test_the_browser_and_client_share_cores_and_the_servers_and_capture_do_not(self):
        src = inspect.getsource(wf_real.worker)
        # The client's controller (and so its data plane) on the client cores, the others not.
        self.assertIn('cpus = a.client_cpus if role == "client" else a.server_cpus', src)
        # Every page load (browser and driver) on the client cores.
        self.assertIn("pinned(a.client_cpus, run + list(argv))", src)
        # A dedicated recorder CPU is preferred; old standalone invocations
        # retain their explicit server-CPU fallback.
        self.assertIn("subprocess.Popen(pinned(a.capture_cpus or a.server_cpus, sniff))", src)

    def test_the_wire_clock_gets_fq_and_its_counters_are_kept(self):
        src = inspect.getsource(wf_real.worker)
        # fq on both clocked ends: the client's link (upstream) and the relay's (downstream).
        self.assertIn('for ns, dev in [(capture_ns, capture_dev), ("rel", "cb")]:', src)
        self.assertIn('"qdisc", "replace", "dev", dev, "root", "fq"', src)
        self.assertIn('"clock.json"', src)

    def test_a_failed_load_keeps_the_browsers_reason_and_the_chain_keeps_its_logs(self):
        # Round 1 of the re-run lost 37 clock loads to a bare "WebDriverException" and the
        # chain's RAM-only logs vanished with its namespaces; neither may happen again.
        self.assertIn("status,error=type(e).__name__,str(e).strip()[:300]", wf_real.BROWSE)
        self.assertIn("status=status,error=error,", wf_real.BROWSE)
        src = inspect.getsource(wf_real.worker)
        self.assertIn('rt.glob("*.lab.log")', src)
        self.assertIn('(out / f"{role}.{f.name}").write_bytes', src)

    def test_each_run_records_the_hosts_power_state(self):
        power = wf_real.host_power()
        self.assertEqual(set(power), {"on_mains", "governor"})


if __name__ == "__main__":
    unittest.main()
