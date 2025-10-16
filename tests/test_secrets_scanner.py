import unittest
from unittest.mock import Mock, patch
import os
import shutil
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from src.secrets_scanner import SecretsScanner
from src.data_classes import Finding


class TestSecretsScanner(unittest.TestCase):
    def setUp(self):
        self.mock_registry = Mock()
        self.mock_llm = Mock()

        self.mock_pattern = Mock()
        self.mock_pattern.name = "api_key_generic"
        self.mock_pattern.description = "API keys"
        self.mock_pattern.regex = r'api_key\s*=\s*["\']([^"\']+)["\']'
        self.mock_pattern.confidence_boost = 0.5

        self.mock_registry.get_pattern.return_value = [self.mock_pattern]

        self.patcher1 = patch(
            "src.secrets_scanner.PatternRegistry", return_value=self.mock_registry
        )
        self.patcher2 = patch(
            "src.secrets_scanner.LLMAnalyzer", return_value=self.mock_llm
        )

        self.patcher1.start()
        self.patcher2.start()

        self.addCleanup(self.patcher1.stop)
        self.addCleanup(self.patcher2.stop)

    def test_get_content_hash(self):
        scanner = SecretsScanner(repo_path="dummy")
        content = "test content for hashing"
        hash1 = scanner._get_content_hash(content)
        hash2 = scanner._get_content_hash(content)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 16)

    def test_apply_regex_patterns_match(self):
        scanner = SecretsScanner(repo_path="dummy")
        content = 'line1\napi_key = "secret123"\nline3'
        findings = scanner._apply_regex_patterns(content)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 2)
        self.assertIn("secret123", findings[0]["snippet"])
        self.assertEqual(findings[0]["type"], "api_key_generic")
        self.assertEqual(findings[0]["confidence"], "high")

    def test_apply_regex_patterns_no_match(self):
        scanner = SecretsScanner(repo_path="dummy")
        content = "safe code no secrets"
        findings = scanner._apply_regex_patterns(content)
        self.assertEqual(findings, [])

    def test_deduplicate_findings(self):
        scanner = SecretsScanner(repo_path="dummy")
        findings = [
            {"line": 1, "type": "api_key_generic", "snippet": "duplicate snippet"},
            {"line": 1, "type": "api_key_generic", "snippet": "duplicate snippet"},
            {"line": 2, "type": "password", "snippet": "another"},
        ]
        dedup = scanner._deduplicate_findings(findings)
        self.assertEqual(len(dedup), 2)

    def test_redact_snippet_key_type(self):
        scanner = SecretsScanner(repo_path="dummy", redaction=1)
        snippet = 'api_key = "verylongsecret123456"'
        redacted = scanner.redact_snippet(snippet, "api_key_generic")

        self.assertIn("very", redacted)
        self.assertIn("*", redacted)
        self.assertIn("3456", redacted)

    def test_redact_snippet_no_redaction(self):
        scanner = SecretsScanner(repo_path="dummy", redaction=0)
        snippet = 'password = "secret"'
        redacted = scanner.redact_snippet(snippet, "password")
        self.assertEqual(redacted, snippet)

    def test_redact_snippet_password(self):
        scanner = SecretsScanner(repo_path="dummy", redaction=1)
        snippet = 'password = "mysecretpass"'
        redacted = scanner.redact_snippet(snippet, "password")
        self.assertEqual(redacted, 'password = "********"')

    @patch("src.secrets_scanner.Repo")
    def test_analyze_content_regex_and_llm_cache_miss(self, mock_repo_class):
        mock_repo = Mock()
        mock_repo.working_dir = "/fake"
        scanner = SecretsScanner(repo_path="dummy")
        scanner.repo = mock_repo

        content = 'api_key = "secret"'

        self.mock_llm.analyze_chunk.return_value = [
            {
                "line": 1,
                "snippet": "llm find",
                "type": "llm_type",
                "confidence": "medium",
                "rationale": "llm",
            }
        ]

        findings = scanner._analyze_content(content, "commit123", "file.py")

        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any(f.finding_type == "api_key_generic" for f in findings))
        self.assertEqual(scanner.stats["files_processed"], 1)
        self.assertEqual(len(scanner._analyzed_cache), 1)

    def test_analyze_content_cache_hit(self):
        scanner = SecretsScanner(repo_path="dummy")
        content = "cached content"
        cache_key = f"file.py:{scanner._get_content_hash(content)}"
        mock_finding = Finding(
            commit_hash="old",
            file_path="old.py",
            line_number=1,
            snippet="cached",
            finding_type="type",
            confidence="high",
            rationale="cached",
            author=None,
            date=None,
            is_uncommitted=False,
        )
        scanner._analyzed_cache[cache_key] = [mock_finding]

        findings = scanner._analyze_content(
            content, "commit123", "file.py", author="test@author", date="2023-01-01"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].commit_hash, "commit123")
        self.assertEqual(findings[0].file_path, "file.py")
        self.assertEqual(findings[0].author, "test@author")
        self.assertEqual(findings[0].date, "2023-01-01")
        self.assertEqual(scanner.stats["cache_hits"], 1)

    @patch("src.secrets_scanner.os.path.exists", return_value=True)
    @patch.object(shutil, "rmtree")
    def test_cleanup_temp_files(self, mock_rmtree, mock_exists):
        scanner = SecretsScanner(repo_path="https://remote.git")
        scanner.temp_dir = "/fake/temp"
        scanner._cleanup_temp_files()
        mock_rmtree.assert_called_with("/fake/temp", ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
