#!/usr/bin/env python3
"""Регрессии выбора, повторного запуска и проверки артефактов GitHub Actions."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("ci-release-artifacts.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
SHA = "a" * 40
REPO = "t0fox/r2o"
RUN = 45029595692
REPO_ID = 1423800872


def workflow(**overrides):
    return dict(path=release.WORKFLOW, head_sha=SHA, head_branch="main", event="push",
                head_repository={"full_name": REPO}, id=RUN, run_attempt=1,
                status="completed", conclusion="success") | overrides


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.jobs = [dict(id=index, name=f"Выпуск ABI — {abi}", run_id=RUN,
                          run_attempt=1, head_sha=SHA, status="completed", conclusion="success")
                     for index, abi in enumerate(release.ABIS, 1)]
        self.assets = [dict(id=index, name=release.artifact_name(SHA, abi, 1), expired=False,
                            digest="sha256:" + "c" * 64,
                            workflow_run=dict(id=RUN, head_sha=SHA, head_branch="main",
                                              repository_id=REPO_ID, head_repository_id=REPO_ID))
                       for index, abi in enumerate(release.ABIS, 10)]

    def select(self, attempt=1):
        return release.select_artifacts(self.jobs, self.assets, SHA, RUN, attempt, REPO_ID)

    def test_skips_forks_pull_requests_and_other_shas(self):
        runs = [workflow(), workflow(id=RUN + 1, event="pull_request"),
                workflow(id=RUN + 2, head_sha="b" * 40),
                workflow(id=RUN + 3, head_repository={"full_name": "fork/r2o"})]
        self.assertEqual(release.select_run(runs, SHA, REPO)["id"], RUN)

    def test_cancelled_or_running_ci_cannot_publish(self):
        for state, result in (("completed", "cancelled"), ("in_progress", None), ("completed", "failure")):
            with self.subTest(result=result), self.assertRaisesRegex(ValueError, "не завершился успешно"):
                release.select_run([workflow(), workflow(id=RUN + 1, status=state, conclusion=result)], SHA, REPO)

    def test_partial_retry_uses_latest_successful_job_per_abi(self):
        abi = release.ABIS[0]
        expected = release.artifact_name(SHA, abi, 2)
        self.jobs.append(self.jobs[0] | {"id": 100, "run_attempt": 2})
        self.assets.append(self.assets[0] | {"id": 100, "name": expected})
        selected = self.select(2)
        self.assertEqual(len(selected), 12)
        self.assertEqual(selected[expected], {"abi": abi, "id": 100, "attempt": 2})
        self.assertIn(release.artifact_name(SHA, release.ABIS[1], 1), selected)
        self.jobs[-1]["conclusion"] = "cancelled"
        with self.assertRaisesRegex(ValueError, "не прошло проверку"):
            self.select(2)

    def test_artifact_missing_or_ambiguous(self):
        asset = self.assets.pop()
        with self.assertRaisesRegex(ValueError, "ровно один артефакт"):
            self.select()
        self.assets.extend((asset, asset | {"id": 100}))
        with self.assertRaisesRegex(ValueError, "ровно один артефакт"):
            self.select()

    def test_expired_wrong_origin_or_missing_digest(self):
        asset = self.assets[0]
        for change in ({"expired": True}, {"digest": None},
                       {"workflow_run": asset["workflow_run"] | {"head_sha": "b" * 40}}):
            self.assets[0] = asset | change
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "не соответствует"):
                self.select()

    def test_verifies_binary_bytes_and_elf_abi_before_packaging(self):
        abi = "x86_64-musl"
        name = release.artifact_name(SHA, abi, 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            downloads = root / "artifacts"
            directory = downloads / name
            directory.mkdir(parents=True)
            subprocess.run(["cc", "-static", "-x", "c", "-o", directory / release.BINARIES[0], "-"],
                           input=b"int main(void) { return 0; }", check=True)
            for binary in release.BINARIES[1:]:
                shutil.copyfile(directory / release.BINARIES[0], directory / binary)
            selected = {name: {"abi": abi, "attempt": 1}}
            release.main("record", str(directory), SHA, str(RUN), abi, "1")
            release.prepare(downloads, root / "verified", selected, SHA, RUN)
            self.assertEqual(len(list((root / "verified" / abi).iterdir())), 7)
            target = directory / release.BINARIES[0]
            target.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "не совпадает SHA-256"):
                release.prepare(downloads, root / "bad-hash", selected, SHA, RUN)
            release.main("record", str(directory), SHA, str(RUN), abi, "1")
            with self.assertRaises(subprocess.CalledProcessError):
                release.prepare(downloads, root / "bad-elf", selected, SHA, RUN)
            release.main("record", str(directory), "b" * 40, str(RUN), abi, "1")
            with self.assertRaisesRegex(ValueError, "метаданные артефакта"):
                release.prepare(downloads, root / "bad-sha", selected, SHA, RUN)


if __name__ == "__main__":
    unittest.main()
