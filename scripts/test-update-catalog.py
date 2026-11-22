#!/usr/bin/env python3
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BUILDER = Path(__file__).with_name("build-update-catalog.py")


def release(tag, order):
    return {
        "release_id": tag,
        "metadata": {"format": 2, "config_format": 1, "state_format": 1, "sequence": order},
    }


class ReleaseCatalogTest(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory(prefix="test-update-catalog-", dir=Path.cwd())
        self.addCleanup(workspace.cleanup)
        self.work = Path(workspace.name)

    def run_builder(self, previous, published, current):
        old = self.work / "old.json"
        old.write_text(json.dumps({"format": 1, "releases": previous}), encoding="utf-8")
        tags = self.work / "tags.txt"
        tags.write_text("\n".join(published), encoding="utf-8")
        (self.work / "latest.json").write_text(json.dumps(current), encoding="utf-8")
        old_tag = previous[0]["release_id"] if previous else "r2o-legacy"
        return subprocess.run(
            [sys.executable, "-B", BUILDER, old_tag, old, tags, self.work],
            capture_output=True, check=False,
        )

    def catalog(self):
        return json.loads((self.work / "catalog.json").read_bytes())["releases"]

    def test_first_signed_generation_excludes_legacy(self):
        base = release("r2o-base", 1)
        result = self.run_builder([], ["r2o-legacy"], base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.catalog(), [base])

    def test_releases_removed_from_github_are_not_in_new_catalog(self):
        base, older, latest = release("r2o-base", 1), release("r2o-older", 2), release("r2o-latest", 3)
        result = self.run_builder([older, base], ["r2o-older"], latest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.catalog(), [latest, older])

    def test_replayed_sequence_and_duplicate_release_are_rejected(self):
        oldest, latest = release("r2o-base", 1), release("r2o-latest", 2)
        for current in [release("r2o-next", 2), release("r2o-base", 3)]:
            with self.subTest(current=current):
                result = self.run_builder([latest, oldest], ["r2o-base", "r2o-latest"], current)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.work / "catalog.json").exists())


if __name__ == "__main__":
    unittest.main()
