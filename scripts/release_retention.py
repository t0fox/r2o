#!/usr/bin/env python3
"""Keep the signed update catalog and GitHub release retention in sync."""
import json
from pathlib import Path
import re
import sys

KEEP_RELEASES = 15
RELEASE_TAG = re.compile(r"r2o-\d{8}-\d{4}-[0-9a-f]{7}-\d+(?:-\d+)?")


def ordered_releases(pages, latest_tag):
    releases = []
    tags, ids = set(), set()
    for page in pages:
        for release in page:
            tag = release["tag_name"]
            if (release["draft"] or release["prerelease"]
                    or not RELEASE_TAG.fullmatch(tag)):
                continue
            release_id = release["id"]
            if (not release["published_at"] or not isinstance(release_id, int)
                    or release_id <= 0 or tag in tags or release_id in ids):
                raise ValueError(f"Invalid or duplicate published release: {tag}")
            tags.add(tag)
            ids.add(release_id)
            releases.append(release)
    if latest_tag not in tags:
        raise ValueError(f"Latest published R2O release is missing: {latest_tag}")
    # GitHub returns UTC ISO-8601 published_at timestamps. Pin the explicit latest.
    return sorted(releases, key=lambda r: (r["tag_name"] == latest_tag,
                  r["published_at"], r["id"]), reverse=True)


def has_signature(release):
    return any(asset["name"] == "latest.json.sig" for asset in release["assets"])


def catalog_candidates(pages, latest_tag):
    # Reserve one slot for the release that is about to be published.
    return [r["tag_name"] for r in ordered_releases(pages, latest_tag)[:KEEP_RELEASES - 1]
            if has_signature(r)]


def prune_candidates(pages, latest_tag, catalog):
    releases = ordered_releases(pages, latest_tag)
    kept = {r["tag_name"] for r in releases[:KEEP_RELEASES] if has_signature(r)}
    catalog_tags = [r["release_id"] for r in catalog["releases"]]
    if (catalog["format"] != 1 or not catalog_tags or catalog_tags[0] != latest_tag
            or len(catalog_tags) != len(set(catalog_tags))
            or not set(catalog_tags) <= kept):
        raise ValueError("Refusing to prune: signed catalog references a release outside retention")
    # Delete oldest first. Never touch drafts, prereleases, or unrelated tags.
    return [(r["id"], r["tag_name"]) for r in reversed(releases[KEEP_RELEASES:])]


def main():
    mode, latest_tag, pages_path, *rest = sys.argv[1:]
    pages = json.loads(Path(pages_path).read_bytes())
    if mode == "before" and not rest:
        for tag in catalog_candidates(pages, latest_tag):
            print(tag)
    elif mode == "after" and len(rest) == 1:
        catalog = json.loads(Path(rest[0]).read_bytes())
        for release_id, tag in prune_candidates(pages, latest_tag, catalog):
            print(f"{release_id}\t{tag}")
    else:
        raise SystemExit("Usage: release_retention.py before|after latest_tag releases.json [catalog.json]")


if __name__ == "__main__":
    main()
