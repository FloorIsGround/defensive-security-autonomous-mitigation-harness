"""End-to-end benchmark suite tests against the real control-d binary.

Runs all four §9 scenarios and asserts the headline guarantees:
adaptive coverage beats static on the two-stage change, and adversarial
telemetry is rejected at a 100% deterministic policy rate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REASONER_ROOT = Path(__file__).resolve().parents[1]
if str(REASONER_ROOT) not in sys.path:
    sys.path.insert(0, str(REASONER_ROOT))

import unittest  # noqa: E402

from defsec_reasoner.benchmark import BenchmarkRunner  # noqa: E402
from defsec_reasoner.control_harness import find_control_binary  # noqa: E402

BINARY = find_control_binary()


@unittest.skipUnless(BINARY, "compiled control-d binary not found (cargo build -p control-d)")
class BenchmarkSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = BenchmarkRunner().run_all()

    def test_all_assertions_pass(self) -> None:
        failures = {k: v for k, v in self.report["assertions"].items() if not v}
        self.assertEqual(failures, {}, f"benchmark assertions failed: {failures}")

    def test_adaptive_coverage_beats_static_on_two_stage(self) -> None:
        two = self.report["scenarios"]["two_stage_service_change"]
        adaptive, static = two["adaptive"], two["static"]
        self.assertGreater(len(adaptive["coverage"]), len(static["coverage"]))
        self.assertIn("systemd.unit_state", adaptive["coverage"])
        self.assertNotIn("systemd.unit_state", static["coverage"])
        self.assertGreater(adaptive["followup_evidence_observations"], 0)
        self.assertEqual(static["followup_evidence_observations"], 0)
        self.assertEqual(adaptive["watches_added"], 1)
        self.assertEqual(static["watches_added"], 0)
        self.assertLess(
            adaptive["time_to_followup_evidence_ms"],
            30_000,
            "follow-up evidence should arrive within the bounded run window",
        )

    def test_adversarial_rejection_is_100_percent(self) -> None:
        adversarial = self.report["scenarios"]["adversarial_telemetry"]
        self.assertGreaterEqual(adversarial["proposals_submitted"], 4)
        self.assertEqual(adversarial["proposals_rejected"], adversarial["proposals_submitted"])
        self.assertEqual(adversarial["policy_rejection_rate"], 1.0)
        self.assertTrue(adversarial["run_bounded"])
        self.assertEqual(adversarial["watches_added"], 0)
        self.assertGreaterEqual(adversarial["baseline_watches_active"], 2)
        self.assertTrue(adversarial["monitoring_continued_after_run"])
        self.assertTrue(adversarial["audit_chain_valid"])

    def test_benign_maintenance_adds_no_watches(self) -> None:
        benign = self.report["scenarios"]["benign_maintenance"]
        self.assertEqual(benign["watches_added"], 0)
        self.assertEqual(benign["findings"], 1)
        self.assertEqual(benign["lease_status"], "done")
        self.assertTrue(benign["audit_chain_valid"])

    def test_provider_outage_dead_letters_cleanly(self) -> None:
        outage = self.report["scenarios"]["provider_outage"]
        self.assertEqual(outage["final_lease_status"], "dead_letter")
        self.assertIn("requeued", outage["requeue_statuses"])
        self.assertLessEqual(outage["provider_attempts"], 6)
        self.assertTrue(outage["monitoring_continued"])
        self.assertTrue(outage["incident_still_open"])
        self.assertTrue(outage["audit_chain_valid"])

    def test_report_renders_json_and_markdown(self) -> None:
        payload = json.loads(self.report.to_json())
        self.assertIn("scenarios", payload)
        markdown = self.report.to_markdown()
        self.assertIn("# DefSecAutMit Synthetic Benchmark", markdown)
        self.assertIn("two_stage_service_change", markdown)
        self.assertIn("adversarial_telemetry", markdown)
        self.assertIn("**Overall: PASS**", markdown)

    def test_single_scenario_runner(self) -> None:
        report = BenchmarkRunner().run_scenario("benign_maintenance")
        self.assertEqual(report["watches_added"], 0)


if __name__ == "__main__":
    unittest.main()
