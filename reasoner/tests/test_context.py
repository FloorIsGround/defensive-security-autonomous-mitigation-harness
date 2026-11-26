"""Compaction for collector sets and trigger-diff extraction."""

import unittest

from defsec_reasoner.context import compact_observation, trigger_diff


class ContextTests(unittest.TestCase):
    def test_compacts_generic_top_level_and_delta_sets(self):
        row = {
            "observation_id": 2,
            "payload": {
                "kind": "delta",
                "data": {"flows": [{"flow_key": key} for key in ("z", "b", "a")]},
                "packages": [{"package_key": "ssh"}, {"package_key": "curl"}],
                "events": [{"message": "unchanged"}],
            },
        }
        compacted = compact_observation(row, max_items=2)
        flows = compacted["payload"]["data"]["flows"]
        self.assertEqual(flows["total"], 3)
        self.assertEqual(flows["shown"], 2)
        self.assertEqual(flows["omitted"], 1)
        self.assertEqual(flows["items"], [{"flow_key": "a"}, {"flow_key": "b"}])
        packages = compacted["payload"]["packages"]
        self.assertEqual(packages["items"], [{"package_key": "curl"}, {"package_key": "ssh"}])
        self.assertEqual(compacted["payload"]["events"], row["payload"]["events"])
        focused = compact_observation(row, focus_keys={"z"})
        self.assertEqual(focused["payload"]["data"]["flows"]["items"], [{"flow_key": "z"}])
        self.assertEqual(focused["payload"]["packages"]["items"], [])
        self.assertEqual(len(row["payload"]["data"]["flows"]), 3)

    def test_extracts_all_diff_categories(self):
        expected = {"added": ["a"], "removed": ["b"], "modified": ["c"]}
        self.assertEqual(trigger_diff({"predicate": {"details": expected}}), expected)
