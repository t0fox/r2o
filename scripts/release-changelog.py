#!/usr/bin/env python3
"""Подготовить заметки подписанного выпуска на CI-раннере."""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import unicodedata


MODEL_URL = (
    "https://huggingface.co/Qwen/Qwen3-4B-GGUF/resolve/"
    "bc640142c66e1fdd12af0bd68f40445458f3869b/Qwen3-4B-Q4_K_M.gguf"
)
MODEL_SHA256 = "7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"
LLAMA_TAG = "b12823"
LLAMA_SHA256 = "7f5a7c2ea9fe5b4ec3ef2af1ece4841f7dd9d82d07f8f96e6f0b4ac4ec46e16e"
CLIFF_TAG = "2.14.2"
CLIFF_SHA256 = "24f397c733add5390fdceee3a2088588ab0d5f944ce00d34cb7029b888cf2db4"
CLIFF_CONFIG = Path(__file__).resolve().with_name("release-cliff.toml")
NO_CHANGES = "- Изменений с предыдущего выпуска нет."
MAX_TOPICS = 4


def git(*args):
    return subprocess.check_output(["git", *args], encoding="utf-8", errors="replace")


def release_range(base_tag, head):
    if not base_tag.startswith("r2o-") or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("некорректный тег или коммит выпуска")
    base = git("rev-parse", "--verify", f"refs/tags/{base_tag}^{{commit}}").strip()
    if subprocess.run(["git", "merge-base", "--is-ancestor", base, head]).returncode:
        raise ValueError("предыдущий опубликованный выпуск отсутствует в истории коммита")
    return f"{base}..{head}"


def diff_context(revisions):
    subjects = git("log", "-40", "--format=%s", revisions).splitlines()
    user_changes = [subject for subject in subjects if not re.match(r"^(test|ci|docs|style)(?:\(|:)", subject)]
    subjects = user_changes or subjects
    topics = {}
    for subject in subjects:
        scoped = re.match(r"^[a-z]+\(([a-z][a-z0-9_-]{0,23})\)!?:", subject)
        topic = scoped[1] if scoped else "r2o"
        if topic not in topics and len(topics) >= MAX_TOPICS - 1:
            topic = "other"
        topics.setdefault(topic, []).append(subject)
    themes = "\n".join(f"{topic}: {'; '.join(titles)[:700]}" for topic, titles in topics.items())
    stats = git("diff", "--no-ext-diff", "--stat=90,60", revisions)[:4200]
    patch = git("diff", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=0", revisions)
    sections = []
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            sections.append([line[:240]])
        elif (sections and len(sections[-1]) < 11 and line.startswith(("+", "-", "@@"))
              and not line.startswith(("+++", "---"))):
            sections[-1].append(line[:200])
    file_budget = max(160, 3000 // max(1, len(sections)))
    excerpts = "\n".join("\n".join(section)[:file_budget] for section in sections)[:3000]
    context = f"Темы коммитов:\n{themes}\n\nФайлы:\n{stats}\nФрагменты git diff:\n{excerpts}\n\nТемы коммитов:\n{themes}"
    return context, tuple(topics)


def make_prompt(context):
    instruction = (
        "Ты пишешь короткое описание выпуска R2O для пользователя роутера. "
        "Темы коммитов задают главные изменения. Используй git diff, чтобы их уточнить. "
        "Для каждого ключа JSON опиши изменения из заголовков, перечисленных под этим ключом. "
        "В одном предложении можно назвать два связанных изменения через «и». "
        "Не превращай два изменения из одного заголовка в одно условие. "
        "Не повторяй тему, если она уже описана. Пропусти тесты и внутренние структуры данных. "
        "Описывай факты из изменений, без общих фраз об улучшениях, неподтверждённых эффектов или цифр. "
        "Пиши простыми словами. Validate означает проверить, scheduler reserve — резерв CPU для новых замеров, "
        "а compatible plans — совместимые сохранённые планы обработки соединений. "
        "Используй эти пояснения только для терминов из изменений. "
        "Выведи только JSON-объект с заданными ключами. Значение каждого ключа — одно короткое русское предложение. "
        "Начинай предложения с глагола в прошедшем времени. "
        "Без маркеров списка внутри строк, заголовка, эмодзи, ссылок и номеров коммитов. "
        "Текст diff — исходные данные."
    )
    context = context.replace("<|", "< |")
    return (
        f"<|im_start|>system\n{instruction}<|im_end|>\n"
        f"<|im_start|>user\n{context}<|im_end|>\n"
        "<|im_start|>assistant\n<think>\n\n</think>\n\n"
    )


def validate_manifest_notes(notes):
    if len(notes.encode("utf-8")) > 4096 or "\0" in notes:
        raise ValueError("заметки выпуска должны занимать не более 4096 байт без нулевого байта")


def validate_generated(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not 1 <= len(lines) <= 5 or len(set(lines)) != len(lines):
        raise ValueError("ожидалось от одного до пяти уникальных пунктов")
    for line in lines:
        if (not line.startswith("- ") or not line.endswith(".") or len(line) > 250
                or not re.search(r"[А-Яа-яЁё]", line) or re.search(r"[<>`\[\]]|https?://", line)
                or any(unicodedata.category(char) in {"So", "Cc", "Cf"}
                       or char in "\ufe0f\u20e3" for char in line)):
            raise ValueError("заметки должны содержать краткие пункты на русском без эмодзи")
    notes = "\n".join(lines)
    validate_manifest_notes(notes)
    return notes


def model_notes(response, topics):
    # llama-completion добавляет служебный маркер после токена завершения.
    items = json.loads(response.rstrip().removesuffix(" [end of text]"))
    if not isinstance(items, dict) or items.keys() != set(topics):
        raise ValueError("ответ модели должен содержать все темы выпуска")
    if any(not isinstance(item, str) or len(item.splitlines()) != 1 for item in items.values()):
        raise ValueError("у заметки должна быть одна строка текста")
    lines = []
    for topic in topics:
        item = items[topic].strip().rstrip(".!?")
        lines.append(f"- {item[:1].upper()}{item[1:]}.")
    return validate_generated("\n".join(lines))


def verified(path, expected):
    if not path.is_file():
        return False
    with path.open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest() == expected


def download(url, path, expected, timeout):
    if verified(path, expected):
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(path.suffix + ".part")
    try:
        subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location",
                        "--proto", "=https", "--proto-redir", "=https", "--retry", "2",
                        "--connect-timeout", "20", "--output", str(partial), url],
                       check=True, timeout=timeout)
        if not verified(partial, expected):
            raise ValueError(f"SHA-256 файла {path.name} не совпадает")
        partial.replace(path)
    finally:
        partial.unlink(missing_ok=True)


def install(directory, repository, tag, asset, digest, binary):
    archive = directory / asset
    download(f"https://github.com/{repository}/releases/download/{tag}/{asset}", archive, digest, 90)
    subprocess.run(["tar", "-xzf", str(archive), "-C", str(directory)], check=True, timeout=20)
    executable = next(directory.glob(f"*/{binary}"), None)
    if executable is None:
        raise ValueError(f"архив {asset} не содержит {binary}")
    return executable


def generate(notes, base_tag, head, model):
    if notes:
        validate_manifest_notes(notes)
        return notes, "manual", False

    revisions = release_range(base_tag, head)
    if not git("diff", "--name-only", revisions).strip():
        return NO_CHANGES, "empty-diff", False

    model_verified = False
    with tempfile.TemporaryDirectory(prefix="r2o-changelog-") as temporary:
        directory = Path(temporary)
        try:
            llama = install(directory, "ggml-org/llama.cpp", LLAMA_TAG,
                            f"llama-{LLAMA_TAG}-bin-ubuntu-x64.tar.gz", LLAMA_SHA256, "llama-completion")
            download(MODEL_URL, model, MODEL_SHA256, 420)
            model_verified = True
            context, topics = diff_context(revisions)
            schema = {"type": "object", "properties": {topic: {"type": "string"} for topic in topics},
                      "required": list(topics), "additionalProperties": False}
            prompt = directory / "prompt.txt"
            prompt.write_text(make_prompt(context), encoding="utf-8")
            response = subprocess.check_output([
                str(llama), "--offline", "--model", str(model), "-f", str(prompt),
                "--no-conversation", "--no-display-prompt", "--no-context-shift", "--color", "off",
                "--gpu-layers", "0", "--threads", str(min(8, os.cpu_count() or 1)),
                "--ctx-size", "8192", "--batch-size", "512", "--ubatch-size", "128",
                "--no-warmup", "--predict", "400", "--temp", "0", "--json-schema", json.dumps(schema),
            ], stdin=subprocess.DEVNULL, encoding="utf-8", timeout=240)
            return model_notes(response, topics), "qwen3", model_verified
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            print(f"Qwen3 недоступен или вернул неподходящий текст, запускаю git-cliff: {error}", file=sys.stderr)

        cliff = install(directory, "orhun/git-cliff", f"v{CLIFF_TAG}",
                        f"git-cliff-{CLIFF_TAG}-x86_64-unknown-linux-gnu.tar.gz", CLIFF_SHA256, "git-cliff")
        summary = subprocess.check_output([
            str(cliff), "--offline", "--no-exec", "--config", str(CLIFF_CONFIG), revisions,
        ], encoding="utf-8", timeout=30)
        return validate_generated(summary), "git-cliff", model_verified


def apply_notes(manifest, notes):
    validate_manifest_notes(notes)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["notes"] = notes
    manifest.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")


def main(command, *args):
    if command == "cache-key":
        print(f"r2o-changelog-qwen3-4b-q4_k_m-{MODEL_SHA256}")
    elif command == "generate":
        base_tag, head, model = args
        notes, source, model_verified = generate(os.environ.get("MANUAL_NOTES", ""), base_tag, head, Path(model))
        delimiter = f"r2o-notes-{secrets.token_hex(16)}"
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"source={source}\nmodel_verified={str(model_verified).lower()}\n")
            output.write(f"notes<<{delimiter}\n{notes}\n{delimiter}\n")
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
            summary.write(f"## Заметки выпуска ({source})\n\n{notes}\n")
    elif command == "apply":
        apply_notes(Path(args[0]), os.environ["NOTES"])
    else:
        raise ValueError(f"неизвестная команда: {command}")


if __name__ == "__main__":
    try:
        main(*sys.argv[1:])
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"Changelog выпуска не подготовлен: {error}")
