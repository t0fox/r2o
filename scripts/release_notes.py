#!/usr/bin/env python3
"""Load reviewed release notes from the immutable release tree.

Each .changes/*.json file contains ``component`` and ``notes``. A fragment added
with its product change needs no commit field. Historical backfills must name
the exact source commit; the commit which adds the backfill is not its source.
"""

import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import unicodedata


MAX_FRAGMENT_BYTES = 16 * 1024
COMMIT = re.compile(r"[0-9a-f]{40}")
RUSSIAN = re.compile(r"[А-Яа-яЁё]")


def git(*args):
    return subprocess.check_output(["git", *args])


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"повторяющееся поле JSON: {key}")
        result[key] = value
    return result


def parse_fragment(raw):
    if len(raw) > MAX_FRAGMENT_BYTES:
        raise ValueError("фрагмент превышает 16 КиБ")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)


def plain_text(text):
    return not (re.search(r"[<>]", text)
                or any(unicodedata.category(char) in {"So", "Cc", "Cf", "Cs"}
                       or char in "\ufe0f\u20e3\u2028\u2029" for char in text))


def validate_fragment(fragment, component=None):
    """Validate schema; at release time also enforce the source component."""
    if (not isinstance(fragment, dict)
            or not {"component", "notes"} <= fragment.keys()
            or fragment.keys() - {"component", "notes", "commit"}):
        raise ValueError("нужны поля component, notes и, при необходимости, commit")
    title = fragment["component"]
    if not isinstance(title, str) or not title.strip() or title != title.strip() or not plain_text(title):
        raise ValueError("component должен быть непустым названием компонента")
    if component is not None and title != component:
        raise ValueError(f"component должен совпадать с компонентом исходного изменения: {component}")
    if "commit" in fragment and (not isinstance(fragment["commit"], str)
                                 or not COMMIT.fullmatch(fragment["commit"])):
        raise ValueError("commit должен содержать полный SHA исходного коммита")
    notes = fragment["notes"]
    if not isinstance(notes, list) or not 1 <= len(notes) <= 8:
        raise ValueError("notes должен содержать от одного до восьми пунктов")
    for note in notes:
        if (not isinstance(note, str) or note != note.strip() or not note.endswith(".")
                or len(note) > 700 or not RUSSIAN.search(note) or not plain_text(note)
                or re.match(r"(?:[-*+•]|\d+[.)])\s", note)):
            raise ValueError("пункты должны быть законченными русскими предложениями до 700 символов "
                             "без маркеров списка, HTML, управляющих символов и эмодзи")
    return fragment


def load_release_notes(revisions, head, changes):
    """Return ({change ID: bullet lines}, {change ID: source fragment paths}).

    Read blobs only from ``head``. An implicit fragment belongs to its sole
    addition commit in ``revisions``; an explicit historical fragment belongs
    only to its named source commit. Neither can cover code outside the range.
    Malformed current fragments raise ValueError so the caller can report the
    problem and fall back. Malformed stale fragments do not poison new releases.
    """
    if not COMMIT.fullmatch(head) or not revisions or revisions.startswith("-"):
        raise ValueError("нужны неизменяемый SHA выпуска и диапазон исходных коммитов")
    commits = set(git("log", "--format=%H", revisions, "--").decode("ascii").splitlines())
    by_commit = {}
    for change in changes:
        for sha in change["commits"]:
            if sha in by_commit and by_commit[sha]["id"] != change["id"]:
                raise ValueError("один исходный коммит принадлежит нескольким изменениям")
            if sha in commits:
                by_commit[sha] = change
    summaries, metadata = {}, {}
    entries = git("ls-tree", "-r", "-z", "-l", head, "--", ".changes")
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        header, raw_path = entry.split(b"\t", 1)
        path = raw_path.decode("utf-8")
        parsed_path = PurePosixPath(path)
        if parsed_path.parent != PurePosixPath(".changes") or parsed_path.suffix != ".json":
            continue
        mode, kind, blob, size = header.split()
        touched = bool(git("log", "-1", "--format=%H", revisions, "--", path).strip())
        current_source = False
        try:
            if mode not in {b"100644", b"100755"} or kind != b"blob":
                raise ValueError("фрагмент должен быть обычным JSON-файлом")
            if int(size) > MAX_FRAGMENT_BYTES:
                raise ValueError("фрагмент превышает 16 КиБ")
            fragment = parse_fragment(git("cat-file", "blob", blob.decode("ascii")))
            if not isinstance(fragment, dict):
                raise ValueError("фрагмент должен быть объектом JSON")
            source = fragment.get("commit")
            if "commit" in fragment:
                if not isinstance(source, str) or not COMMIT.fullmatch(source):
                    raise ValueError("commit должен содержать полный SHA исходного коммита")
            else:
                additions = git("log", "--diff-filter=A", "--format=%H", revisions,
                                "--", path).decode("ascii").splitlines()
                if not additions:
                    if touched:
                        validate_fragment(fragment)
                    continue
                if len(additions) != 1:
                    raise ValueError("у фрагмента без commit должно быть ровно одно добавление в диапазоне")
                source = additions[0]
            change = by_commit.get(source)
            current_source = change is not None
            if change is None:
                # A note from an older release, an unknown explicit SHA or a
                # separately added unbound fragment cannot cover current code.
                if touched:
                    validate_fragment(fragment)
                continue
            validate_fragment(fragment, change["component"])
        except (ValueError, UnicodeError) as error:
            if touched or current_source:
                raise ValueError(f"{path}: {error}") from error
            continue
        lines = summaries.setdefault(change["id"], [])
        for note in fragment["notes"]:
            line = f"- {note}"
            if line not in lines:
                lines.append(line)
        metadata.setdefault(change["id"], []).append(path)
    return summaries, metadata


def check_fragments(directory=Path(".changes")):
    """Check worktree fragment schema before CI; ownership is checked at release."""
    if not directory.exists():
        return 0
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError(".changes должен быть каталогом с обычными JSON-файлами")
    count = 0
    for path in sorted(directory.glob("*.json")):
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError("фрагмент должен быть обычным JSON-файлом")
            if path.stat().st_size > MAX_FRAGMENT_BYTES:
                raise ValueError("фрагмент превышает 16 КиБ")
            validate_fragment(parse_fragment(path.read_bytes()))
        except (ValueError, UnicodeError) as error:
            raise ValueError(f"{path}: {error}") from error
        count += 1
    return count


if __name__ == "__main__":
    try:
        if sys.argv[1:] != ["check"]:
            raise ValueError("использование: release_notes.py check")
        print(f"Проверено фрагментов описания выпуска: {check_fragments()}")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"Некорректные заметки выпуска: {error}")
