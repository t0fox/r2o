#!/usr/bin/env python3
"""Регрессии полноты описания, границ выпуска и резервного режима."""

import importlib.util
from contextlib import chdir, contextmanager
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


def change(number, component="Discovery"):
    sha = f"{number:012x}" + "0" * 28
    return {
        "id": sha[:12], "commits": [sha], "subject": f"fix(discovery): change {number}",
        "message": f"Fix independent connection case {number}.", "component": component,
        "files": [f"src/change-{number}.rs"],
        "patch": f"diff --git a/src/change-{number}.rs b/src/change-{number}.rs\n"
                 f"@@ -1 +1 @@\n-old_{number}();\n+new_{number}();\n",
    }


def reply(changes):
    return json.dumps({item["id"]: [{"action": "Исправили",
                                    "detail": f"обработку ошибки номер {index} при подключении к сайту"}]
                       for index, item in enumerate(changes)}, ensure_ascii=False)


@contextmanager
def repository():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)

        def git(*args):
            return subprocess.check_output(["git", "-C", directory, "-c", "user.name=R2O",
                                            "-c", "user.email=r2o@example.invalid", *args], text=True)

        def commit(subject, filename="src/change.rs", content=None):
            path = root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content if content is not None else subject + "\n", encoding="utf-8")
            git("add", filename)
            git("commit", "-qm", subject)
            return git("rev-parse", "HEAD").strip()

        git("init", "-qb", "main")
        commit("initial state")
        git("tag", "r2o-published")
        with chdir(directory):
            yield git, commit


class ChangelogTests(unittest.TestCase):
    def test_manual_notes_bypass_history_and_tools(self):
        notes = "Ручное описание\n\nВторая строка."
        with patch.object(changelog, "git", side_effect=AssertionError("git не нужен")):
            result = changelog.generate(notes, "", "", Path("/unused"))
        self.assertEqual(result["notes"], notes)
        self.assertEqual(result["body"], notes)
        self.assertEqual(result["source"], "manual")
        self.assertFalse(result["model_verified"])

    def test_generated_notes_require_complete_russian_bullets(self):
        self.assertEqual(changelog.validate_generated(f"\n{EXAMPLE}\n"), EXAMPLE)
        for bad in ("## Выпуск", "- Fixed a bug.", "- Исправили ⚠️.", "- Исправили",
                    "- <think>Ответ.</think>."):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                changelog.validate_generated(bad)

    def test_full_generated_description_is_not_limited_to_five_bullets_or_manifest_size(self):
        bullets = [f"- Исправили случай {number}: " + "проверку состояния соединения " * 8 + "."
                   for number in range(12)]
        description = "\n".join(bullets)
        self.assertGreater(len(description.encode("utf-8")), 4096)
        self.assertEqual(changelog.validate_generated(description), description)

    def test_each_change_in_the_same_component_keeps_its_own_notes(self):
        changes = [change(number) for number in range(1, 7)]
        summaries = changelog.model_notes(reply(changes), changes)
        body = changelog.render_body(changes, summaries)
        self.assertEqual(set(summaries), {item["id"] for item in changes})
        for lines in summaries.values():
            for line in lines:
                self.assertIn(line, body)
        self.assertEqual(sum(line.startswith("- ") for line in body.splitlines()), 6)

    def test_one_change_can_explain_multiple_independent_effects(self):
        changes = [change(1)]
        response = {changes[0]["id"]: [
            {"action": "Исправили", "detail": "передачу RAW TCP через POSTROUTING"},
            {"action": "Уточнили", "detail": "проверку подтверждения после отправки пакета"},
            {"action": "Исправили", "detail": "загрузку каталога после сохранения старым контроллером"},
        ]}
        notes = changelog.model_notes(json.dumps(response, ensure_ascii=False), changes)
        self.assertEqual(len(notes[changes[0]["id"]]), 3)
        self.assertIn("POSTROUTING", notes[changes[0]["id"]][0])
        self.assertIn("каталога", notes[changes[0]["id"]][2])

    def test_model_must_cover_every_known_change_with_nonempty_notes(self):
        changes = [change(1), change(2)]
        valid = json.loads(reply(changes))
        invalid = [
            {changes[0]["id"]: valid[changes[0]["id"]]},
            valid | {"unknown": valid[changes[0]["id"]]},
            valid | {changes[1]["id"]: []},
            valid | {changes[1]["id"]: [{"action": "Исправили", "detail": ""}]},
        ]
        for response in invalid:
            with self.subTest(response=response), self.assertRaises(ValueError):
                changelog.model_notes(json.dumps(response), changes)

    def test_llama_end_marker_is_not_published(self):
        changes = [change(1)]
        clean = changelog.model_notes(reply(changes), changes)
        marked = changelog.model_notes(reply(changes) + " [end of text]\n\n", changes)
        self.assertEqual(marked, clean)

    def test_distinct_ids_cannot_mask_missing_detail_with_the_same_sentence(self):
        changes = [change(1), change(2)]
        response = {item["id"]: [{"action": "Исправили", "detail": "обработку соединения с сервером"}]
                    for item in changes}
        with self.assertRaises(ValueError):
            changelog.model_notes(json.dumps(response), changes)

    def test_published_wording_regressions_are_rejected(self):
        changes = [change(1)]
        for detail in ("Сгенерировал русские заметки выпуска локально", "повторил совместимые планы",
                       "отчет о CPU отдельно от резервного CPU"):
            with self.subTest(detail=detail), self.assertRaises(ValueError):
                changelog.model_notes(json.dumps({changes[0]["id"]:
                                                 [{"action": "Обновили", "detail": detail}]}), changes)

    def test_collection_preserves_more_than_forty_commits_and_four_components(self):
        scopes = ("discovery", "catalog", "telegram", "panel", "keenetic", "dns")
        with repository() as (git, commit):
            expected = {commit(f"feat({scopes[number % len(scopes)]}): independent change {number}",
                               f"src/change-{number}.rs") for number in range(45)}
            revisions = changelog.release_range("r2o-published", git("rev-parse", "HEAD").strip())
            changes, skipped = changelog.collect_changes(revisions)
        self.assertEqual({sha for item in changes for sha in item["commits"]}, expected)
        self.assertGreater(len({item["component"] for item in changes}), 4)
        self.assertFalse(skipped)

    def test_repeated_subject_keeps_both_source_changes(self):
        with repository() as (git, commit):
            subject = "feat(discovery): verify measured TCP segment order over HTTPS"
            first = commit(subject, "src/https.rs", "fn first_implementation() {}\n")
            second = commit(subject, "src/endpoint.rs", "fn second_endpoint_check() {}\n")
            revisions = changelog.release_range("r2o-published", git("rev-parse", "HEAD").strip())
            changes, _ = changelog.collect_changes(revisions)
        self.assertEqual({sha for item in changes for sha in item["commits"]}, {first, second})
        context = "\n".join(item["patch"] for item in changes)
        self.assertIn("first_implementation", context)
        self.assertIn("second_endpoint_check", context)

    def test_release_tooling_does_not_replace_product_changes(self):
        with repository() as (git, commit):
            commit("feat(release): generate Russian changelogs locally", "scripts/release-changelog.py")
            product_sha = commit("fix(panel): report aggregate CPU separately", "src/panel.rs")
            revisions = changelog.release_range("r2o-published", git("rev-parse", "HEAD").strip())
            changes, skipped = changelog.collect_changes(revisions)
        self.assertEqual({sha for item in changes for sha in item["commits"]}, {product_sha})
        self.assertTrue(skipped)

    def test_feature_flag_in_last_file_survives_diff_budget(self):
        patch_text = "\n".join(
            f"diff --git a/src/file-{index}.rs b/src/file-{index}.rs\n@@ -1 +1,80 @@\n"
            + "\n".join(f"+let generated_value_{line} = Value::default();" for line in range(80))
            for index in range(20)
        )
        patch_text += ("\ndiff --git a/router/S99r2o b/router/S99r2o\n@@ -600,0 +601,2 @@\n"
                       "+# The experimental discovery mode is disabled by default.\n"
                       "+R2O_RAW_DISCOVERY=${R2O_RAW_DISCOVERY:-0}\n")
        excerpt = changelog.patch_excerpt(patch_text, budget=3000)
        self.assertIn("R2O_RAW_DISCOVERY=${R2O_RAW_DISCOVERY:-0}", excerpt)
        self.assertIn("disabled by default", excerpt)

    def test_batching_preserves_every_change_when_inputs_are_large(self):
        changes = [change(number) for number in range(1, 10)]
        for item in changes:
            item["patch"] += "+fn some_real_changed_function() {}\n" * 250
        batches = changelog.make_batches(changes)
        self.assertGreater(len(batches), 1)
        self.assertEqual([item["id"] for batch in batches for item in batch],
                         [item["id"] for item in changes])

    def test_compact_notes_fit_utf8_limit_without_cutting_a_bullet(self):
        bullets = [f"- Исправили независимую ошибку {number}: " + "обработку ответа сервера " * 8 + "."
                   for number in range(20)]
        body = "### Discovery\n\n" + "\n".join(bullets)
        self.assertGreater(len(body.encode("utf-8")), 4096)
        compact = changelog.compact_notes(body)
        changelog.validate_manifest_notes(compact)
        self.assertLessEqual(len(compact.encode("utf-8")), 4096)
        self.assertIn("полн", compact.lower())
        retained = [line for line in compact.splitlines() if line.startswith("- ")]
        self.assertTrue(retained)
        self.assertTrue(all(line in bullets for line in retained))
        self.assertEqual(changelog.compact_notes(EXAMPLE), EXAMPLE)

    def test_internal_only_release_does_not_load_model(self):
        with (patch.object(changelog, "release_range", return_value="old..new"),
              patch.object(changelog, "git", return_value="scripts/release-changelog.py"),
              patch.object(changelog, "collect_changes", return_value=([], [{"subject": "fix(release): notes"}])),
              patch.object(changelog, "install", side_effect=AssertionError("бинарник не нужен"))):
            result = changelog.generate("", "r2o-old", "0" * 40, Path("/unused"))
        self.assertEqual(result["notes"], changelog.INTERNAL_ONLY)
        self.assertEqual(result["source"], "internal-only")
        self.assertFalse(result["model_verified"])

    def test_empty_diff_needs_no_model_or_fallback(self):
        with (patch.object(changelog, "release_range", return_value="old..new"),
              patch.object(changelog, "git", return_value=""),
              patch.object(changelog, "install", side_effect=AssertionError("бинарник не нужен"))):
            result = changelog.generate("", "r2o-old", "0" * 40, Path("/unused"))
        self.assertEqual(result["notes"], changelog.NO_CHANGES)
        self.assertEqual(result["source"], "empty-diff")
        self.assertFalse(result["model_verified"])

    def test_later_model_failures_preserve_successful_notes_and_use_concrete_fallback(self):
        changes = [change(number) for number in range(1, 4)]
        successful = {changes[0]["id"]: [EXAMPLE]}
        cliff_context = [{"commits": [{"id": item["commits"][0], "message": item["subject"]}
                                      for item in changes]}]
        with (
            patch.object(changelog, "release_range", return_value="old..new"),
            patch.object(changelog, "git", return_value="src/change.rs"),
            patch.object(changelog, "collect_changes", return_value=(changes, [])),
            patch.object(changelog, "load_release_notes", return_value=({}, {})),
            patch.object(changelog, "make_batches", return_value=[[item] for item in changes]),
            patch.object(changelog, "install", side_effect=[Path("llama-completion"), Path("git-cliff")]),
            patch.object(changelog, "download"),
            patch.object(changelog, "run_model", side_effect=[successful,
                         subprocess.TimeoutExpired("llama-completion", 300), ValueError("неполный JSON")]),
            patch.object(changelog.subprocess, "check_output", return_value=json.dumps(cliff_context)) as cliff,
        ):
            result = changelog.generate("", "r2o-old", "0" * 40, Path("/unused"))
        self.assertIn(EXAMPLE, result["body"])
        self.assertNotIn(changes[0]["subject"], result["body"])
        for item in changes[1:]:
            self.assertIn(item["subject"], result["body"])
        self.assertEqual({item["id"]: item["source"] for item in result["coverage"]["changes"]},
                         {changes[0]["id"]: "qwen3", changes[1]["id"]: "git-cliff",
                          changes[2]["id"]: "git-cliff"})
        self.assertEqual(cliff.call_count, 1)
        self.assertEqual(result["source"], "qwen3+git-cliff")
        self.assertTrue(result["model_verified"])

    def test_missing_model_and_git_cliff_still_preserve_all_source_changes(self):
        changes = [change(number) for number in range(1, 7)]
        with (
            patch.object(changelog, "release_range", return_value="old..new"),
            patch.object(changelog, "git", return_value="src/change.rs"),
            patch.object(changelog, "collect_changes", return_value=(changes, [])),
            patch.object(changelog, "load_release_notes", return_value=({}, {})),
            patch.object(changelog, "install", side_effect=OSError("загрузка недоступна")),
        ):
            result = changelog.generate("", "r2o-old", "0" * 40, Path("/unused"))
        for item in changes:
            self.assertIn(item["subject"], result["body"])
        self.assertEqual(len(result["coverage"]["changes"]), len(changes))
        self.assertEqual(result["source"], "git")
        self.assertFalse(result["model_verified"])

    def test_duplicate_notes_from_separate_batches_fall_back_without_losing_other_results(self):
        changes = [change(number) for number in range(1, 4)]
        independent_note = "- Убрали полное клонирование каталога при синхронизации."
        responses = [{changes[0]["id"]: [EXAMPLE]}, {changes[1]["id"]: [EXAMPLE]},
                     {changes[2]["id"]: [independent_note]}]
        fallback = {item["id"]: [f"- {item['subject']}."] for item in changes[:2]}
        with (
            patch.object(changelog, "release_range", return_value="old..new"),
            patch.object(changelog, "git", return_value="src/change.rs"),
            patch.object(changelog, "collect_changes", return_value=(changes, [])),
            patch.object(changelog, "load_release_notes", return_value=({}, {})),
            patch.object(changelog, "make_batches", return_value=[[item] for item in changes]),
            patch.object(changelog, "install", return_value=Path("llama-completion")),
            patch.object(changelog, "download"),
            patch.object(changelog, "run_model", side_effect=responses),
            patch.object(changelog, "fallback_notes", return_value=(fallback, "git")) as reserve,
        ):
            result = changelog.generate("", "r2o-old", "0" * 40, Path("/unused"))
        self.assertEqual(reserve.call_args.args[0], changes[:2])
        self.assertNotIn(EXAMPLE, result["body"])
        self.assertIn(independent_note, result["body"])
        for item in changes[:2]:
            self.assertIn(item["subject"], result["body"])
        self.assertEqual({item["id"]: item["source"] for item in result["coverage"]["changes"]},
                         {changes[0]["id"]: "git", changes[1]["id"]: "git",
                          changes[2]["id"]: "qwen3"})

    def test_global_model_deadline_keeps_unprocessed_changes_in_fallback(self):
        changes = [change(1), change(2)]
        successful = {changes[0]["id"]: [EXAMPLE]}
        fallback = {changes[1]["id"]: ["- fix(discovery): change 2."]}
        with (
            patch.object(changelog, "release_range", return_value="old..new"),
            patch.object(changelog, "git", return_value="src/change.rs"),
            patch.object(changelog, "collect_changes", return_value=(changes, [])),
            patch.object(changelog, "load_release_notes", return_value=({}, {})),
            patch.object(changelog, "make_batches", return_value=[[item] for item in changes]),
            patch.object(changelog, "install", return_value=Path("llama-completion")),
            patch.object(changelog, "download"),
            patch.object(changelog.time, "monotonic", side_effect=[0, 1, changelog.MODEL_BUDGET_SECONDS + 1]),
            patch.object(changelog, "run_model", return_value=successful) as model,
            patch.object(changelog, "fallback_notes", return_value=(fallback, "git")) as reserve,
        ):
            result = changelog.generate("", "r2o-old", "0" * 40, Path("/unused"))
        model.assert_called_once()
        self.assertEqual(reserve.call_args.args[0], [changes[1]])
        self.assertIn(EXAMPLE, result["body"])
        self.assertIn(fallback[changes[1]["id"]][0], result["body"])

    def test_manifest_update_preserves_fields_and_rejects_oversized_utf8(self):
        original = {"release_id": "r2o-test", "notes": "", "assets": {"mipsel": {"bytes": 64}}}
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "latest.json"
            manifest.write_text(json.dumps(original), encoding="utf-8")
            changelog.apply_notes(manifest, EXAMPLE)
            expected = original | {"notes": EXAMPLE}
            self.assertEqual(json.loads(manifest.read_bytes()), expected)
            for invalid in ("я" * 2049, "текст\0с нулевым байтом"):
                with self.subTest(invalid=invalid[:30]), self.assertRaises(ValueError):
                    changelog.apply_notes(manifest, invalid)
                self.assertEqual(json.loads(manifest.read_bytes()), expected)

    def test_reviewed_fragments_supply_exact_full_body_without_model_or_download(self):
        changes = [change(number) for number in range(1, 4)]
        reviewed = {item["id"]: [
            f"- Исправили отдельный случай {index}-{number}: " + "проверку ответа сервера " * 8 + "."
            for number in range(4)] for index, item in enumerate(changes)}
        provenance = {item["id"]: [f".changes/reviewed-{index}.json"]
                      for index, item in enumerate(changes)}
        expected = "### Discovery\n\n" + "\n".join(line for lines in reviewed.values() for line in lines)
        self.assertGreater(len(expected.encode("utf-8")), 4096)
        with (
            patch.object(changelog, "release_range", return_value="old..new"),
            patch.object(changelog, "git", return_value="src/change.rs"),
            patch.object(changelog, "collect_changes", return_value=(changes, [])),
            patch.object(changelog, "load_release_notes", return_value=(reviewed, provenance)) as fragments,
            patch.object(changelog, "install", side_effect=AssertionError("модель не нужна")),
            patch.object(changelog, "download", side_effect=AssertionError("скачивание не нужно")),
            patch.object(changelog, "run_model", side_effect=AssertionError("генерация не нужна")),
            patch.object(changelog, "fallback_notes", side_effect=AssertionError("резерв не нужен")),
        ):
            result = changelog.generate("", "r2o-old", "0" * 40, Path("/unused"))
        fragments.assert_called_once_with("old..new", "0" * 40, changes)
        self.assertEqual(result["body"], expected)
        self.assertEqual(result["source"], "release-note")
        self.assertFalse(result["model_verified"])
        changelog.validate_manifest_notes(result["notes"])
        self.assertIn("полн", result["notes"].lower())
        for item in result["coverage"]["changes"]:
            self.assertEqual(item["fragments"], provenance[item["id"]])
            self.assertEqual(item["source"], "release-note")

    def test_partial_fragments_are_preserved_when_generated_note_repeats_reviewed_prose(self):
        changes = [change(number) for number in range(1, 4)]
        reviewed = {changes[0]["id"]: [EXAMPLE]}
        independent_note = "- Убрали полное клонирование каталога при синхронизации."
        generated = {changes[1]["id"]: [EXAMPLE], changes[2]["id"]: [independent_note]}
        fallback = {changes[1]["id"]: [f"- {changes[1]['subject']}."]}
        with (
            patch.object(changelog, "release_range", return_value="old..new"),
            patch.object(changelog, "git", return_value="src/change.rs"),
            patch.object(changelog, "collect_changes", return_value=(changes, [])),
            patch.object(changelog, "load_release_notes", return_value=(reviewed, {})),
            patch.object(changelog, "install", return_value=Path("llama-completion")),
            patch.object(changelog, "download"),
            patch.object(changelog, "run_model", return_value=generated) as model,
            patch.object(changelog, "fallback_notes", return_value=(fallback, "git")) as reserve,
        ):
            result = changelog.generate("", "r2o-old", "0" * 40, Path("/unused"))
        model.assert_called_once()
        self.assertEqual(model.call_args.args[2], changes[1:])
        self.assertEqual(reserve.call_args.args[0], [changes[1]])
        self.assertEqual(result["body"].count(EXAMPLE), 1)
        self.assertIn(independent_note, result["body"])
        self.assertIn(changes[1]["subject"], result["body"])
        self.assertEqual({item["id"]: item["source"] for item in result["coverage"]["changes"]},
                         {changes[0]["id"]: "release-note", changes[1]["id"]: "git",
                          changes[2]["id"]: "qwen3"})

    def test_malformed_fragments_fall_back_to_complete_source_list(self):
        changes = [change(1), change(2)]
        with (
            patch.object(changelog, "release_range", return_value="old..new"),
            patch.object(changelog, "git", return_value="src/change.rs"),
            patch.object(changelog, "collect_changes", return_value=(changes, [])),
            patch.object(changelog, "load_release_notes", side_effect=ValueError("некорректный фрагмент")),
            patch.object(changelog, "install", side_effect=OSError("загрузка недоступна")),
        ):
            result = changelog.generate("", "r2o-old", "0" * 40, Path("/unused"))
        for item in changes:
            self.assertIn(item["subject"], result["body"])
        self.assertEqual(len(result["coverage"]["changes"]), len(changes))
        self.assertEqual(result["source"], "git")
        self.assertFalse(result["model_verified"])

    def test_published_tag_controls_range_even_with_newer_local_tag(self):
        with repository() as (git, commit):
            head = commit("feat(discovery): candidate release", content="candidate\n")
            git("tag", "r2o-candidate")
            revisions = changelog.release_range("r2o-published", head)
            changes, _ = changelog.collect_changes(revisions)
        self.assertEqual({sha for item in changes for sha in item["commits"]}, {head})
        self.assertIn("+candidate", changes[0]["patch"])
        self.assertNotIn("initial state", changes[0]["subject"])


if __name__ == "__main__":
    unittest.main()
