"""Provider discovery must remain bounded, offline and incapable of provisioning."""

import copy
import gzip
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

import search_providers as providers
from controller_bridge import Refused, canonical


class ProviderDiscovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = providers.shipped_index()

    def request(self, query="", cursor=None, provider_filter="all"):
        return providers.search(self.index, dict(query=query, cursor=cursor, filter=provider_filter))

    def test_every_registry_entry_is_reachable_once_without_promoting_candidates(self):
        ids, cursor = [], None
        while True:
            page = self.request(cursor=cursor)
            self.assertLessEqual(page["returned"], 50)
            self.assertLessEqual(len(canonical(page)), providers.MAX_RESPONSE)
            for row in page["results"]:
                self.assertFalse(row["can_launch_provisioning"])
                self.assertFalse(row["recipe_available"])
                self.assertEqual(row["documented_capabilities"], "unknown")
                ids.append(row["id"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        self.assertEqual(len(ids), 4825)
        self.assertEqual(len(set(ids)), len(ids))
        self.assertEqual(ids, [r["id"] for r in self.index["providers"]])
        candidate = self.request("hetznercloud/hcloud")["results"][0]
        self.assertTrue(candidate["reviewed_recipe_candidate"])
        self.assertEqual(candidate["tier"], "recipe_candidate")
        self.assertEqual(self.request(provider_filter="reviewed_recipes")["returned"], 0)
        self.assertEqual(self.request(provider_filter="unavailable_non_compute")["returned"], 0)
        self.assertEqual(self.request(provider_filter="unreviewed")["total_matches"], 4825)

    def test_no_network_process_or_query_logging_is_needed(self):
        with (
            mock.patch.object(socket, "socket", side_effect=AssertionError("network forbidden")),
            mock.patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")),
            mock.patch("builtins.print", side_effect=AssertionError("query logging forbidden")),
        ):
            result = self.request("hetzner")
        self.assertGreater(result["returned"], 0)
        self.assertNotIn("query", result)
        self.assertNotIn("command", canonical(result).decode())

    def test_request_cannot_supply_capability_evidence_paths_or_execution(self):
        request = dict(query="", cursor=None, filter="all")
        for key in ("evidence", "recipe", "path", "command", "pin", "can_launch_provisioning"):
            with self.subTest(key=key), self.assertRaises(Refused):
                providers.search(self.index, dict(request, **{key: True}))

    def test_utf8_bounds_control_characters_and_invalid_types_refuse(self):
        self.request("é" * 128)
        for query in ("é" * 129, "\0", "\n", "\x7f", "\ud800", [], None, 17):
            with self.subTest(query=repr(query)), self.assertRaises(Refused):
                self.request(query)
        for value in (None, {}, [], dict(query="", cursor=None, filter="exec")):
            with self.subTest(value=value), self.assertRaises(Refused):
                providers.search(self.index, value)

    def test_cursor_is_bound_to_query_filter_and_index(self):
        token = self.request()["next_cursor"]
        self.assertIsNotNone(token)
        for query, provider_filter in (("a", "all"), ("", "unreviewed")):
            with self.assertRaises(Refused):
                self.request(query, token, provider_filter)
        changed = dict(self.index, index_sha256="0" * 64)
        with self.assertRaises(Refused):
            providers.search(changed, dict(query="", cursor=token, filter="all"))
        for bad in ("", "!", "A" * 513, 3, False):
            with self.subTest(cursor=bad), self.assertRaises(Refused):
                self.request(cursor=bad)

    def test_bundle_requires_a_pinned_digest_and_refuses_tampering(self):
        source = Path(providers.__file__).with_name("provider_data") / "opentofu_registry_index.json.gz"
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "index.gz"
            p.write_bytes(source.read_bytes())
            with self.assertRaises(Refused):
                providers.load_index(p, None)
            with self.assertRaises(Refused):
                providers.load_index(p, "0" * 64)
            payload = gzip.decompress(p.read_bytes()).replace(b"hcloud", b"tcloud", 1)
            p.write_bytes(gzip.compress(payload))
            with self.assertRaises(Refused):
                providers.load_index(p, providers.INDEX_SHA256)

    def test_symlinks_corrupt_archives_and_expansion_bombs_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "index.gz"
            p.symlink_to(Path(providers.__file__))
            with self.assertRaises(Refused):
                providers.load_index(p, providers.INDEX_SHA256)
            p.unlink()
            for value in (b"not gzip", gzip.compress(b"x" * (providers.MAX_INDEX_BYTES + 1))):
                p.write_bytes(value)
                with self.assertRaises(Refused):
                    providers.load_index(p, providers.INDEX_SHA256)

    def test_malformed_structure_and_duplicate_entries_refuse_even_with_a_matching_outer_digest(self):
        for mutation in ("count", "duplicate", "schema", "namespace"):
            document = copy.deepcopy(self.index)
            if mutation == "count":
                document["providers_total"] += 1
            elif mutation == "duplicate":
                document["providers"][1] = document["providers"][0]
            elif mutation == "schema":
                document["schema"] = True
            else:
                document["providers"][0]["namespace"] = "../../etc"
            payload = json.dumps(document).encode()
            with tempfile.TemporaryDirectory() as directory:
                p = Path(directory) / "index.gz"
                p.write_bytes(gzip.compress(payload))
                with self.subTest(mutation=mutation), self.assertRaises(Refused):
                    providers.load_index(p, hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    unittest.main()
