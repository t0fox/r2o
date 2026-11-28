#!/usr/bin/env python3
"""Проверки диапазона, резервного режима и метаданных заметок выпуска."""

import importlib.util
from contextlib import chdir
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("changelog", Path(__file__).with_name("release-changelog.py"))
changelog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(changelog)

EXAMPLE = "- Исправили подключение к Telegram."


class ChangelogTests(unittest.TestCase):
    def test_manual_notes_bypass_history_and_tools(self):
        notes = "Ручное описание\n\nВторая строка."
        with patch.object(changelog, "git", side_effect=AssertionError("git не нужен")):
            self.assertEqual(changelog.generate(notes, "", "", Path("/unused")), (notes, "manual", False))

    def test_generated_notes_require_complete_russian_bullets(self):
        self.assertEqual(changelog.validate_generated(f"\n{EXAMPLE}\n"), EXAMPLE)
        for bad in ("## Выпуск", "- Fixed a bug.", "- Исправили ⚠️.", "- Исправили", "- <think>Ответ.</think>."):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                changelog.validate_generated(bad)

    def test_fallback_after_timeout_or_invalid_model_output(self):
        for llama in (subprocess.TimeoutExpired("llama-completion", 240), "случайный текст"):
            with (
                self.subTest(llama=llama),
                patch.object(changelog, "release_range", return_value="old..new"),
                patch.object(changelog, "git", return_value="src.rs"),
                patch.object(changelog, "install", side_effect=(Path("llama-completion"), Path("git-cliff"))),
                patch.object(changelog, "download"),
                patch.object(changelog.subprocess, "check_output", side_effect=(llama, EXAMPLE)) as run,
            ):
                result = changelog.generate("", "r2o-old", "0" * 40, Path("/unused"))
                self.assertEqual(result, (EXAMPLE, "git-cliff", True))
                self.assertEqual(run.call_args.args[0][0], "git-cliff")
                self.assertEqual(run.call_args.args[0][-1], "old..new")

    def test_llama_end_marker_is_not_published(self):
        with (
            patch.object(changelog, "release_range", return_value="old..new"),
            patch.object(changelog, "git", return_value="src.rs"),
            patch.object(changelog, "install", return_value=Path("llama-completion")) as install,
            patch.object(changelog, "download"),
            patch.object(changelog.subprocess, "check_output",
                         return_value=json.dumps({"r2o": {"action": "Исправили", "detail": "подключение к Telegram"}},
                                                 ensure_ascii=False) + " [end of text]\n\n"),
        ):
            self.assertEqual(changelog.generate("", "r2o-old", "0" * 40, Path("/unused")),
                             (EXAMPLE, "qwen3", True))
            install.assert_called_once()

    def test_published_wording_is_rejected(self):
        for detail in ("Сгенерировал русские заметки выпуска локально", "повторил совместимые планы",
                       "отчет о CPU отдельно от резервного CPU"):
            with self.subTest(detail=detail), self.assertRaises(ValueError):
                changelog.model_notes(json.dumps({"r2o": {"action": "Обновили", "detail": detail}}), ("r2o",))

    def test_release_automation_does_not_become_a_user_facing_topic(self):
        with patch.object(changelog, "git", side_effect=(
            "feat(release): generate Russian changelogs locally\nfix(panel): show CPU\n", "", ""
        )):
            context, topics = changelog.diff_context("old..new")
        self.assertEqual(topics, ("panel",))
        self.assertNotIn("generate Russian changelogs", context)

    def test_internal_only_release_does_not_load_model(self):
        with (patch.object(changelog, "release_range", return_value="old..new"),
              patch.object(changelog, "git", side_effect=("release.yml", "fix(changelog): validate notes")),
              patch.object(changelog, "install", side_effect=AssertionError("бинарник не нужен"))):
            self.assertEqual(changelog.generate("", "r2o-old", "0" * 40, Path("/unused")),
                             (changelog.INTERNAL_ONLY, "internal-only", False))

    def test_empty_diff_needs_no_model_or_fallback(self):
        with (
            patch.object(changelog, "release_range", return_value="old..new"),
            patch.object(changelog, "git", return_value=""),
            patch.object(changelog, "install", side_effect=AssertionError("бинарник не нужен")),
        ):
            self.assertEqual(changelog.generate("", "r2o-old", "0" * 40, Path("/unused")),
                             (changelog.NO_CHANGES, "empty-diff", False))

    def test_signed_manifest_gets_the_same_notes_without_changing_other_fields(self):
        original = {"release_id": "r2o-test", "notes": "", "assets": {"mipsel": {"bytes": 64}}}
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "latest.json"
            manifest.write_text(json.dumps(original), encoding="utf-8")
            changelog.apply_notes(manifest, EXAMPLE)
            self.assertEqual(json.loads(manifest.read_bytes()), original | {"notes": EXAMPLE})
            with self.assertRaises(ValueError):
                changelog.apply_notes(manifest, "я" * 2049)
            self.assertEqual(json.loads(manifest.read_bytes()), original | {"notes": EXAMPLE})

    def test_published_tag_controls_the_range_even_with_newer_local_tags(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(["git", "-C", directory, "-c", "user.name=R2O",
                                                "-c", "user.email=r2o@example.invalid", *args], text=True)

            git("init", "-q")
            path = root / "change.txt"
            for name in ("older", "published", "candidate"):
                path.write_text(name, encoding="utf-8")
                git("add", path.name)
                git("commit", "-qm", name)
                if name != "older":
                    git("tag", f"r2o-{name}")
            head = git("rev-parse", "HEAD").strip()
            with chdir(directory):
                revisions = changelog.release_range("r2o-published", head)
                context, topics = changelog.diff_context(revisions)
            self.assertIn("+candidate", context)
            self.assertNotIn("older", context)
            self.assertEqual(topics, ("r2o",))


if __name__ == "__main__":
    unittest.main()
