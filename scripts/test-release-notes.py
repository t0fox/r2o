#!/usr/bin/env python3
"""Regression checks for release-fragment ownership and immutable snapshots."""

from contextlib import chdir
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).with_name("release_notes.py").resolve()
spec = importlib.util.spec_from_file_location("release_notes", HELPER)
notes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notes)

COMPONENT = "Discovery и подключения"
FIRST = "Исправили повторное подключение после смены сети."
SECOND = "Добавили проверку полного ответа при подключении к сайту."


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="r2o-release-notes-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        context = chdir(self.root)
        context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.git("init", "-q")
        self.write("source.rs", "base\n")
        self.base = self.commit("initial source")

    def git(self, *args):
        return subprocess.check_output(["git", "-c", "user.name=R2O test",
                                        "-c", "user.email=r2o@example.invalid", *args],
                                       encoding="utf-8", stderr=subprocess.PIPE).strip()

    def write(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding="utf-8")

    def fragment(self, name, lines=None, **extra):
        fragment = {"component": COMPONENT, "notes": lines or [FIRST]} | extra
        self.write(f".changes/{name}.json", json.dumps(fragment, ensure_ascii=False))

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def change(self, sha):
        return {"id": sha[:12], "commits": [sha], "component": COMPONENT}

    def load(self, head, changes, base=None):
        return notes.load_release_notes(f"{base or self.base}..{head}", head, changes)

    def test_fragment_added_with_product_change_keeps_reviewed_text(self):
        line = "Добавили экспериментальный RAW TCP Discovery; режим включается отдельно через R2O_RAW_DISCOVERY=1."
        self.write("source.rs", "product change\n")
        self.fragment("raw-discovery", [line])
        source = self.commit("feat(discovery): add optional raw discovery")
        change = self.change(source)
        original = deepcopy(change)
        summaries, metadata = self.load(source, [change])
        self.assertEqual(summaries, {source[:12]: [f"- {line}"]})
        self.assertEqual(metadata, {source[:12]: [".changes/raw-discovery.json"]})
        self.assertEqual(change, original)

    def test_old_implicit_fragment_is_not_replayed_in_new_release(self):
        self.fragment("old")
        previous = self.commit("feat(discovery): first change")
        self.write("source.rs", "second change\n")
        self.fragment("new", [SECOND])
        current = self.commit("fix(discovery): second change")
        summaries, metadata = self.load(current, [self.change(current)], base=previous)
        self.assertEqual(summaries, {current[:12]: [f"- {SECOND}"]})
        self.assertEqual(metadata, {current[:12]: [".changes/new.json"]})

    def test_explicit_backfill_belongs_only_to_named_product_commit(self):
        self.write("source.rs", "legacy product change\n")
        source = self.commit("fix(discovery): legacy product change")
        self.fragment("backfill", commit=source)
        head = self.commit("docs: explain earlier change")
        summaries, metadata = self.load(head, [self.change(source)])
        self.assertEqual(summaries, {source[:12]: [f"- {FIRST}"]})
        self.assertEqual(metadata, {source[:12]: [".changes/backfill.json"]})
        # Even a caller-provided source record cannot put old code into the range.
        self.assertEqual(self.load(head, [self.change(source)], base=source), ({}, {}))

    def test_unbound_later_fragment_does_not_claim_earlier_code(self):
        self.write("source.rs", "product change without notes\n")
        source = self.commit("feat(discovery): code first")
        self.fragment("late")
        head = self.commit("docs: add notes separately")
        self.assertEqual(self.load(head, [self.change(source)]), ({}, {}))

    def test_unknown_and_stale_explicit_commits_never_cover_current_code(self):
        self.write("source.rs", "current change\n")
        self.fragment("current", [SECOND])
        source = self.commit("fix(discovery): current change")
        self.fragment("unknown", commit="f" * 40)
        self.fragment("stale", commit=self.base)
        head = self.commit("docs: add unrelated historical notes")
        summaries, metadata = self.load(head, [self.change(source)])
        self.assertEqual(summaries, {source[:12]: [f"- {SECOND}"]})
        self.assertEqual(metadata, {source[:12]: [".changes/current.json"]})

    def test_current_invalid_fragment_is_rejected(self):
        self.write("source.rs", "source for malformed historical note\n")
        source = self.commit("fix(discovery): source")
        bad_fragments = [
            "{bad json",
            '{"component":"Discovery и подключения","component":"Telegram","notes":["Исправили подключение."]}',
            json.dumps({"component": COMPONENT, "notes": [FIRST], "commit": source, "unknown": True}),
            json.dumps({"component": "Telegram", "notes": [FIRST], "commit": source}),
            json.dumps({"component": COMPONENT, "notes": [FIRST], "commit": source[:7]}),
            json.dumps({"component": COMPONENT, "notes": ["- " + FIRST], "commit": source}),
            json.dumps({"component": COMPONENT, "notes": ["Добавили <script>код</script>."], "commit": source}),
            json.dumps({"component": COMPONENT, "notes": ["Добавили проверку 🚀."], "commit": source}),
            json.dumps({"component": COMPONENT, "notes": ["Исправили\nподключение."], "commit": source}),
        ]
        for index, raw in enumerate(bad_fragments):
            with self.subTest(raw=raw):
                self.write(".changes/bad.json", raw)
                head = self.commit(f"test malformed note {index}")
                with self.assertRaisesRegex(ValueError, r"\.changes/bad.json"):
                    self.load(head, [self.change(source)])

    def test_malformed_stale_fragment_does_not_poison_new_release(self):
        self.write(".changes/old.json", "{bad stale json")
        previous = self.commit("old malformed notes")
        self.write("source.rs", "new source\n")
        self.fragment("current")
        head = self.commit("fix(discovery): new source")
        summaries, _ = self.load(head, [self.change(head)], base=previous)
        self.assertEqual(summaries, {head[:12]: [f"- {FIRST}"]})

    def test_modifying_old_implicit_fragment_does_not_reassign_it(self):
        self.fragment("old")
        previous = self.commit("feat(discovery): old source")
        self.write("source.rs", "new source\n")
        self.fragment("old", [SECOND])
        head = self.commit("fix(discovery): new source")
        self.assertEqual(self.load(head, [self.change(head)], base=previous), ({}, {}))

    def test_fragments_come_from_head_not_dirty_worktree(self):
        self.write("source.rs", "committed code\n")
        self.fragment("committed")
        head = self.commit("fix(discovery): committed change")
        self.write(".changes/committed.json", "this is not JSON")
        self.fragment("untracked", [SECOND], commit=head)
        summaries, metadata = self.load(head, [self.change(head)])
        self.assertEqual(summaries, {head[:12]: [f"- {FIRST}"]})
        self.assertEqual(metadata, {head[:12]: [".changes/committed.json"]})

    def test_multiple_fragments_and_same_scope_preserve_independent_changes(self):
        self.write("source.rs", "first source\n")
        self.fragment("first-a")
        self.fragment("first-b", [FIRST, SECOND])
        first = self.commit("fix(discovery): first change")
        self.write("source.rs", "second source\n")
        third = "Убрали повторную отправку уже подтверждённого пакета."
        self.fragment("second", [third])
        second = self.commit("fix(discovery): another change")
        summaries, metadata = self.load(second, [self.change(first), self.change(second)])
        self.assertEqual(summaries, {first[:12]: [f"- {FIRST}", f"- {SECOND}"], second[:12]: [f"- {third}"]})
        self.assertEqual(metadata[first[:12]], [".changes/first-a.json", ".changes/first-b.json"])
        self.assertEqual(metadata[second[:12]], [".changes/second.json"])

    def test_deleted_and_readded_implicit_fragment_has_ambiguous_owner(self):
        self.fragment("reused")
        first = self.commit("feat(discovery): first change")
        (self.root / ".changes/reused.json").unlink()
        self.commit("remove fragment")
        self.fragment("reused", [SECOND])
        second = self.commit("feat(discovery): second change")
        with self.assertRaisesRegex(ValueError, "ровно одно добавление"):
            self.load(second, [self.change(first), self.change(second)])

    def test_oversized_and_symlink_fragments_are_rejected(self):
        self.write(".changes/large.json", " " * (notes.MAX_FRAGMENT_BYTES + 1))
        head = self.commit("feat(discovery): oversized fragment")
        with self.assertRaisesRegex(ValueError, "16 КиБ"):
            self.load(head, [self.change(head)])
        (self.root / ".changes/large.json").unlink()
        (self.root / ".changes/link.json").symlink_to("../source.rs")
        head = self.commit("feat(discovery): linked fragment")
        with self.assertRaisesRegex(ValueError, "обычным JSON-файлом"):
            self.load(head, [self.change(head)])

    def test_cli_checks_all_worktree_fragments_and_empty_directory(self):
        command = [sys.executable, "-B", str(HELPER), "check"]
        empty = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(empty.returncode, 0, empty.stderr)
        self.fragment("valid", commit="a" * 40)
        valid = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertIn("1", valid.stdout)
        self.fragment("invalid", ["Fixed an English-only issue."], commit="b" * 40)
        invalid = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("invalid.json", invalid.stderr)
        self.assertNotIn("Traceback", invalid.stderr)


if __name__ == "__main__":
    unittest.main()
