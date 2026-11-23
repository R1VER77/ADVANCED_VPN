"""cypherpunkctl.firmware_coprocessor: the read-only Intel ME / AMD PSP report in `cypherpunk doctor`."""

import tempfile
import unittest
from pathlib import Path

import cypherpunkctl


def machine(tmp, vendor, ver=None, hfsts1=None):
    root = Path(tmp)
    (root / "cpuinfo").write_text("processor\t: 0\nvendor_id\t: %s\n" % vendor)
    if ver is not None:
        mei = root / "sys/class/mei/mei0"
        mei.mkdir(parents=True)
        (mei / "fw_ver").write_text("0:%s\n0:%s\n" % (ver, ver))
        (mei / "fw_status").write_text("%08X\n80210506\n" % hfsts1)
    return root / "sys", root / "cpuinfo"


class FirmwareCoprocessorTests(unittest.TestCase):
    def report(self, *args, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            return cypherpunkctl.firmware_coprocessor(*machine(tmp, *args, **kw))

    def test_this_laptops_csme_12_is_reported_active_and_too_new_for_me_cleaner(self):
        r = self.report("GenuineIntel", "12.0.20.1307", 0x90000245)  # read from the owner's VAIO
        self.assertIn("Intel ME 12.0.20.1307, normal", r)
        self.assertIn("too new for me_cleaner", r)
        self.assertIn("tier 3 wants it neutralized", r)

    def test_an_me_11_is_one_me_cleaner_recognises(self):
        self.assertIn("me_cleaner recognises it", self.report("GenuineIntel", "11.8.50.3399", 0x90000245))

    def test_a_non_normal_mode_is_named_and_not_flagged(self):
        r = self.report("GenuineIntel", "11.8.50.3399", 0x90030245)  # mode 3 in bits 19:16
        self.assertIn("soft temporary disable", r)
        self.assertNotIn("tier 3 wants", r)

    def test_amd_reports_the_psp(self):
        self.assertIn("AMD PSP", self.report("AuthenticAMD"))

    def test_intel_without_the_mei_interface_says_so(self):
        self.assertIn("ME interface not visible", self.report("GenuineIntel"))

    def test_an_unreadable_status_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as tmp:
            sysfs, cpu = machine(tmp, "GenuineIntel", "12.0.1.1", 0)
            (sysfs / "class/mei/mei0/fw_status").write_text("garbage\n")
            self.assertEqual(cypherpunkctl.firmware_coprocessor(sysfs, cpu), "Intel ME present (unreadable)")


if __name__ == "__main__":
    unittest.main()
