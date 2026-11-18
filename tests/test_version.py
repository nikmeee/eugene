import re
import unittest
from pathlib import Path

from eugene import __version__


ROOT = Path(__file__).resolve().parents[1]


class VersionTests(unittest.TestCase):
    def test_documentation_screenshots_use_current_version(self):
        expected = {"v" + __version__}
        for path in (ROOT / "docs").glob("*.svg"):
            versions = set(re.findall(r"v\d+\.\d+\.\d+", path.read_text()))
            if versions:
                self.assertEqual(versions, expected, path.name)


if __name__ == "__main__":
    unittest.main()
