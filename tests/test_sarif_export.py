import unittest
from unittest.mock import patch, mock_open

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from src.sarif_export import (
    export_to_sarif,
    _generate_results,
    _generate_rules,
    _map_level,
)


class TestSarifExporter(unittest.TestCase):
    def setUp(self):
        self.sample_report = {
            "findings_by_commit": {
                "abc123": [
                    {
                        "finding_type": "api_key",
                        "confidence": "high",
                        "rationale": "Potential API key found",
                        "file_path": "src/config.py",
                        "line_number": 42,
                        "snippet": "API_KEY = 'abc123'",
                        "author": "dev@example.com",
                        "date": "2023-01-01",
                    }
                ],
                "uncommitted": [
                    {
                        "finding_type": "password",
                        "confidence": "low",
                        "rationale": "Hardcoded password",
                        "file_path": "local/settings.py",
                        "line_number": 10,
                        "snippet": "password = 'secret'",
                        "author": "local",
                        "date": "2023-01-02",
                    }
                ],
            }
        }

    def test_map_level(self):
        self.assertEqual(_map_level("high"), "error")
        self.assertEqual(_map_level("Medium"), "warning")
        self.assertEqual(_map_level("low"), "note")
        self.assertEqual(_map_level("unknown"), "note")

    def test_generate_rules(self):
        rules = _generate_rules(self.sample_report)
        self.assertEqual(len(rules), 2)
        rule_ids = {r["id"] for r in rules}
        self.assertIn("api_key", rule_ids)
        self.assertIn("password", rule_ids)

        api_rule = next(r for r in rules if r["id"] == "api_key")
        self.assertEqual(api_rule["defaultConfiguration"]["level"], "error")
        self.assertIn("security", api_rule["properties"]["tags"])

    def test_generate_results(self):
        results = _generate_results(self.sample_report)
        self.assertEqual(len(results), 2)

        committed_result = results[0]
        self.assertEqual(committed_result["ruleId"], "api_key")
        self.assertEqual(committed_result["level"], "error")
        self.assertEqual(
            committed_result["locations"][0]["physicalLocation"]["region"]["startLine"],
            42,
        )
        self.assertEqual(
            committed_result["partialFingerprints"]["commitHash"], "abc123"
        )
        self.assertEqual(committed_result["properties"]["commit"], "abc123")

        uncommitted_result = results[1]
        self.assertEqual(
            uncommitted_result["partialFingerprints"]["commitHash"], "uncommitted"
        )
        self.assertEqual(uncommitted_result["properties"]["confidence"], "low")

    @patch("builtins.open", new_callable=mock_open)
    @patch("json.dump")
    def test_export_to_sarif(self, mock_json_dump, mock_file_open):
        output_file = "test.sarif"
        returned_file = export_to_sarif(self.sample_report, output_file)

        self.assertEqual(returned_file, output_file)
        mock_file_open.assert_called_once_with(output_file, "w", encoding="utf-8")
        mock_json_dump.assert_called_once()

        sarif_arg = mock_json_dump.call_args[0][0]
        self.assertEqual(sarif_arg["version"], "2.1.0")
        self.assertEqual(
            sarif_arg["runs"][0]["tool"]["driver"]["name"], "Git-Secrets-Scanner"
        )
        self.assertEqual(len(sarif_arg["runs"][0]["results"]), 2)
        self.assertEqual(len(sarif_arg["runs"][0]["tool"]["driver"]["rules"]), 2)


if __name__ == "__main__":
    unittest.main()
