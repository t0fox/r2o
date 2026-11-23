#!/usr/bin/env python3
import unittest
from release_retention import KEEP_RELEASES, catalog_candidates, prune_candidates


def github_release(i, **changes):
    release = {"id": i, "tag_name": f"r2o-20261123-2014-{i:07x}-{i}",
               "published_at": f"2026-11-23T20:{i // 60:02d}:{i % 60:02d}Z",
               "draft": False, "prerelease": False,
               "assets": [{"name": "latest.json.sig"}]}
    release.update(changes)
    return release


def signed_catalog(tags):
    return {"format": 1, "releases": [{"release_id": tag} for tag in tags]}


class ReleaseRetentionTest(unittest.TestCase):
    def test_first_cleanup_and_rolling_limit(self):
        old = [github_release(i) for i in range(1, 95)]
        current = github_release(95)
        tags = catalog_candidates([old[:40], old[40:]], old[-1]["tag_name"])
        self.assertEqual(len(tags), KEEP_RELEASES - 1)
        self.assertEqual(tags, [r["tag_name"] for r in reversed(old[-14:])])
        catalog = signed_catalog([current["tag_name"], *tags])
        plan = prune_candidates([old, [current]], current["tag_name"], catalog)
        self.assertEqual([i for i, _ in plan], list(range(1, 81)))
        next_release = github_release(96)
        remaining = [*old[-14:], current]
        tags = catalog_candidates([remaining], current["tag_name"])
        plan = prune_candidates([[*remaining, next_release]], next_release["tag_name"],
                                signed_catalog([next_release["tag_name"], *tags]))
        self.assertEqual([i for i, _ in plan], [81])

    def test_ignores_unrelated_and_unpublished_releases(self):
        current = github_release(1)
        others = [github_release(2, draft=True), github_release(3, prerelease=True),
                  github_release(4, tag_name="v1.0.0")]
        self.assertEqual(prune_candidates([[current, *others]], current["tag_name"],
                         signed_catalog([current["tag_name"]])), [])

    def test_refuses_to_prune_catalog_reference_or_missing_latest(self):
        releases = [github_release(i) for i in range(1, 18)]
        latest = releases[-1]["tag_name"]
        with self.assertRaises(ValueError):
            prune_candidates([releases], latest, signed_catalog([latest, releases[0]["tag_name"]]))
        with self.assertRaises(ValueError):
            prune_candidates([releases], "missing", signed_catalog(["missing"]))
        with self.assertRaises(ValueError):
            prune_candidates([releases], latest, signed_catalog([releases[-2]["tag_name"]]))

    def test_keeps_explicit_latest_and_filters_unsigned_catalog_candidates(self):
        releases = [github_release(i) for i in range(1, 18)]
        releases[-1]["assets"] = []
        latest = releases[0]["tag_name"]
        tags = catalog_candidates([releases], latest)
        self.assertEqual(tags[0], latest)
        self.assertNotIn(releases[-1]["tag_name"], tags)
        self.assertEqual(len(tags), KEEP_RELEASES - 2)

    def test_rejects_duplicate_release(self):
        current = github_release(1)
        with self.assertRaises(ValueError):
            catalog_candidates([[current], [current]], current["tag_name"])


if __name__ == "__main__":
    unittest.main()
