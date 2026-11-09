"""Documentation gate: every command and option is documented, and no page
documents an option that does not exist."""

import argparse
from pathlib import Path
import re
import unittest

import avpnctl
import cloud
import providers

DOCS = Path(__file__).resolve().parents[1] / "docs" / "cli"
# Options that belong to the Rust front end rather than the controller.
FRONT_END = {"--state", "--json", "--no-color", "--reduced-motion", "--foreground", "--help"}


def subcommands(parser):
    """name -> subparser for one argparse level."""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def options(parser):
    """Every long option a parser accepts, recursively."""
    found = {s for a in parser._actions for s in a.option_strings if s.startswith("--")}
    for sub in subcommands(parser).values():
        found |= options(sub)
    return found - {"--help"}


def documented(page, command=None):
    """Every `--option` a page mentions for `command`. Inline code such as
    `avpn preferences --mode` refers to another command's option, so it is skipped."""
    if command:
        page = re.sub(
            r"`(?:sudo )?avpn(?:ctl)? ([a-z]+)[^`]*`", lambda m: m.group(0) if m.group(1) == command else "", page
        )
        # The installer's options belong to tools/install.py, not to the command.
        page = re.sub(r"`(?:sudo )?python3 tools/install\.py[^`]*`", "", page)
    return set(re.findall(r"(?<![\w-])--[a-z][a-z0-9-]*", page))


class DocsGate(unittest.TestCase):
    def test_every_controller_command_has_a_page_listing_all_its_options(self):
        for name, sub in subcommands(avpnctl.build_parser()).items():
            page = DOCS / (name + ".md")
            self.assertTrue(page.exists(), "docs/cli/%s.md is missing" % name)
            missing = options(sub) - documented(page.read_text())
            self.assertFalse(missing, "%s.md does not document %s" % (name, sorted(missing)))

    def test_controller_pages_document_no_option_that_does_not_exist(self):
        for name, sub in subcommands(avpnctl.build_parser()).items():
            extra = documented((DOCS / (name + ".md")).read_text(), name) - options(sub) - FRONT_END
            self.assertFalse(extra, "%s.md documents unknown options %s" % (name, sorted(extra)))

    def test_cloud_page_matches_the_cloud_parser_both_ways(self):
        page = (DOCS / "cloud.md").read_text()
        parser = cloud.build_parser()
        self.assertFalse(options(parser) - documented(page) - {"--json"})
        self.assertFalse(documented(page, "cloud") - options(parser) - FRONT_END)
        for provider, sub in subcommands(parser).items():
            for kind in subcommands(sub) or {provider: None}:
                self.assertIn("avpn cloud %s" % (provider if kind == provider else provider + " " + kind), page)

    def test_every_controller_command_has_help_text(self):
        for name, sub in subcommands(avpnctl.build_parser()).items():
            for action in sub._actions:
                if action.option_strings and action.option_strings != ["-h", "--help"]:
                    self.assertTrue(action.help, "%s %s has no help text" % (name, action.option_strings))

    def test_overview_lists_every_command_and_topic_page(self):
        overview = (DOCS / "overview.md").read_text()
        for page in DOCS.glob("*.md"):
            if page.stem != "overview":
                self.assertIn("`" + page.stem, overview, "overview.md does not mention %s" % page.stem)

    def test_every_page_links_only_to_existing_topics(self):
        names = {p.stem for p in DOCS.glob("*.md")}
        for page in DOCS.glob("*.md"):
            for ref in re.findall(r"avpn help ([a-z-]+)", page.read_text()):
                if ref not in ("COMMAND", "TOPIC"):
                    self.assertIn(ref, names, "%s.md refers to missing topic %s" % (page.stem, ref))


class CatalogGate(unittest.TestCase):
    def test_get_started_cell_is_generated_from_the_catalog(self):
        shipped = (DOCS.parents[1] / "src/bin/avpn/get_started.txt").read_text()
        self.assertEqual(shipped, providers.get_started_text(), "regenerate: python3 tools/providers.py --generate")

    def test_endpoints_page_is_generated_from_the_catalog(self):
        self.assertEqual((DOCS / "endpoints.md").read_text(), providers.endpoints_page(), "run providers.py --generate")
        for p in providers.PROVIDERS:
            self.assertIn(p["name"], providers.endpoints_page())


if __name__ == "__main__":
    unittest.main()
