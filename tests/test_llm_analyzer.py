import unittest
from unittest.mock import Mock
import logging

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from llm_analyzer import LLMAnalyzer


class TestLLMAnalyzer(unittest.TestCase):
    def setUp(self):
        logging.getLogger().setLevel(logging.CRITICAL)
        self.mock_provider = Mock()
        self.analyzer = LLMAnalyzer(provider=self.mock_provider)

    def test_analyze_chunk_valid_json_response(self):
        self.mock_provider.analyze.return_value = '[{"line": 1, "snippet": "key=abc", "type": "api_key", "confidence": "high", "rationale": "test"}]'

        patterns = [Mock(name="api_key", description="API keys")]
        content = "dummy code with key=abc"

        result = self.analyzer.analyze_chunk(content, patterns)
        expected = [
            {
                "line": 1,
                "snippet": "key=abc",
                "type": "api_key",
                "confidence": "high",
                "rationale": "test",
            }
        ]
        self.assertEqual(result, expected)

    def test_analyze_chunk_empty_response(self):
        self.mock_provider.analyze.return_value = "[]"

        patterns = [Mock(name="password", description="Passwords")]
        content = "safe code"

        result = self.analyzer.analyze_chunk(content, patterns)
        self.assertEqual(result, [])

    def test_analyze_chunk_markdown_wrapped(self):
        self.mock_provider.analyze.return_value = '```json\n[{"line": 2, "snippet": "pass=secret", "type": "password", "confidence": "medium", "rationale": "hardcoded"}]```'

        patterns = [Mock(name="password", description="Passwords")]
        content = "code with pass=secret"

        result = self.analyzer.analyze_chunk(content, patterns)

        expected = [
            {
                "line": 2,
                "snippet": "pass=secret",
                "type": "password",
                "confidence": "medium",
                "rationale": "hardcoded",
            }
        ]
        self.assertEqual(result, expected)

    def test_analyze_chunk_invalid_json_fallback(self):
        self.mock_provider.analyze.return_value = "Not JSON at all"

        patterns = [Mock(name="api_key", description="API keys")]
        content = "code"

        result = self.analyzer.analyze_chunk(content, patterns)
        self.assertEqual(result, [])

    def test_analyze_chunk_exception_in_provider(self):
        self.mock_provider.analyze.side_effect = Exception("Connection error")

        patterns = [Mock(name="api_key", description="API keys")]
        content = "code"

        result = self.analyzer.analyze_chunk(content, patterns)
        self.assertEqual(result, [])

    def test_cleanup_calls_provider(self):
        self.mock_provider.cleanup = Mock()
        self.analyzer.cleanup()
        self.mock_provider.cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
