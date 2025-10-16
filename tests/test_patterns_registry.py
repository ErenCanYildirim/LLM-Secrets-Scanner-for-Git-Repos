import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from src.patterns_registry import PatternRegistry, ScanPattern


class TestPatternRegistry(unittest.TestCase):
    def setUp(self):
        self.registry = PatternRegistry()

    def test_init_loads_defaults(self):
        patterns = self.registry.get_pattern()
        self.assertEqual(
            len(patterns), 23
        )  # default count at time of creation, THIS WILL FAIL once more patterns are added
        self.assertIsInstance(patterns[0], ScanPattern)
        self.assertEqual(patterns[0].name, "aws_access_key")
        self.assertEqual(patterns[0].regex, r"AKIA[0-9A-Z]{16}")
        self.assertEqual(patterns[0].confidence_boost, 0.3)

    def test_add_pattern_appends_correctly(self):
        original_count = len(self.registry.get_pattern())
        new_pattern = ScanPattern(
            name="custom_test_key",
            regex=r"TEST[0-9]{4}",
            keywords=["test", "custom"],
            description="Test Pattern",
            confidence_boost=0.1,
        )
        self.registry.add_pattern(new_pattern)
        patterns = self.registry.get_pattern()
        self.assertEqual(len(patterns), original_count + 1)
        self.assertEqual(patterns[-1].name, "custom_test_key")
        self.assertEqual(patterns[-1].regex, r"TEST[0-9]{4}")

    def test_add_invalid_pattern_type_raises(self):
        with self.assertRaises(TypeError):
            self.registry.add_pattern({"name": "fake"})


if __name__ == "__main__":
    unittest.main()
