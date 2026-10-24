#!/usr/bin/env python3
"""Integration tests against a separately SHA256-verified Gitleaks 8.30.1 binary.

Set GITLEAKS_TEST_BIN to its absolute path. Fixtures never contain real secrets.
"""
import contextlib
import io
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
BIN = os.environ.get("GITLEAKS_TEST_BIN")
def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

payloads = module("trusted_payloads_for_secrets", "scan_payloads.py")
secrets = module("trusted_secrets", "scan_secrets.py")


@unittest.skipUnless(BIN, "set GITLEAKS_TEST_BIN to a verified binary")
class Gitleaks(unittest.TestCase):
    def test_cross_blob_match_cannot_use_first_files_exception(self):
        first = "api_" + "key = "
        second = "mL8DfG4qW2zP7bNcR5tX9sHvA3eJ6yKuC0iB1oZa"
        stream = self.root / "cross.txt"
        stream.write_text(first + "\n" + second + "\n")
        digest = hashlib.sha256(first.encode()).hexdigest()
        stream.with_suffix(".map.json").write_text(json.dumps([
            {"start": 1, "end": 1, "path": "first", "sha256": digest, "commit": "a" * 40},
            {"start": 2, "end": 2, "path": "second", "sha256": hashlib.sha256(second.encode()).hexdigest(), "commit": "a" * 40}]))
        policy = secrets.scanner.Exceptions([{"kind": "secret", "rule": "generic-api-key", "path": "first", "sha256": digest, "reason": "Inert prefix"}])
        result = secrets.scan(Path(BIN), stream, exceptions=policy)
        self.assertEqual(result["audited_exceptions"], 0)
        self.assertTrue(any(row["cross_blob"] for row in result["findings"]))
    def test_deleted_secret_flows_from_git_blobs_to_stdin(self):
        self.git("init", "--template=", "--initial-branch=main")
        self.git("config", "user.name", "Synthetic fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.target / "README").write_text("baseline")
        base = self.commit()
        (self.target / "deleted.txt").write_text(self.fake)
        self.commit()
        (self.target / "deleted.txt").unlink()
        head = self.commit()
        stream = self.root / "historical.txt"
        with contextlib.redirect_stdout(io.StringIO()):
            payloads.audit(payloads.Repository(self.target), base, head, secret_input=stream)
        result = secrets.scan(Path(BIN), stream)
        self.assertTrue(any(row["path"] == "deleted.txt" for row in result["findings"]))

    def test_bedrock_rule_still_detects_its_inert_public_prefix(self):
        marker = "bedrock-api-key-" + "YmVkcm9jay5hbWF6b25hd3MuY29t"
        result = secrets.scan(Path(BIN), self.stream(marker))
        self.assertIn("aws-amazon-bedrock-api-key-short-lived", [row["rule"] for row in result["findings"]])
    def stream(self, data, path="temp/.hidden/data"):
        stream = self.root / "stdin.txt"
        stream.write_text(data + "\n")
        stream.with_suffix(".map.json").write_text(json.dumps([{"start": 1, "end": data.count("\n") + 1,
            "path": path, "commit": "a" * 40, "sha256": hashlib.sha256(data.encode()).hexdigest()}]))
        return stream

    def test_stdin_scans_ignore_files_large_lines_and_svg(self):
        for path in [".gitleaksignore", ".gitleaks.toml", "vendor/image.svg", "node_modules/data", "package-lock.json"]:
            stream = self.stream("x" * 100_000 + "\n" + self.fake + " # gitleaks:allow", path)
            result = secrets.scan(Path(BIN), stream)
            self.assertTrue(result["findings"])
            self.assertEqual(result["findings"][0]["path"], path)
            self.assertNotIn(self.fake, json.dumps(result))

    def test_exact_secret_baseline_is_invalidated_by_one_byte_or_path(self):
        data = self.fake
        stream = self.stream(data)
        policy = secrets.scanner.Exceptions([{"kind": "secret", "rule": "github-pat", "path": "temp/.hidden/data",
            "sha256": hashlib.sha256(data.encode()).hexdigest(), "reason": "Provider-shaped inert fixture"}])
        first = secrets.scan(Path(BIN), stream)
        self.assertTrue(first["findings"])
        rule = first["findings"][0]["rule"]
        policy.rows[0]["rule"] = rule
        self.assertEqual(secrets.scan(Path(BIN), stream, exceptions=policy)["findings"], [])
        self.assertTrue(secrets.scan(Path(BIN), self.stream(data + " "), exceptions=policy)["findings"])
        self.assertTrue(secrets.scan(Path(BIN), self.stream(data, "other/data"), exceptions=policy)["findings"])

    def test_current_kit_and_synthetic_fixture_sources_do_not_self_alert(self):
        texts = []
        mapping = []
        line = 1
        for path in sorted(HERE.iterdir()):
            if not path.is_file():
                continue
            text = path.read_text().rstrip("\n") + "\n"
            lines = text.count("\n")
            mapping.append({"start": line, "end": line + lines - 1, "path": ".github/security/" + path.name,
                "commit": "a" * 40, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
            texts.append(text)
            line += lines
        stream = self.root / "kit.txt"
        stream.write_text("".join(texts))
        stream.with_suffix(".map.json").write_text(json.dumps(mapping))
        self.assertEqual(secrets.scan(Path(BIN), stream)["findings"], [])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="test-gitleaks-", dir=HERE)
        self.root = Path(self.tmp.name)
        self.snapshot = self.root / "snapshot"
        self.target = self.snapshot / "files"
        self.target.mkdir(parents=True)
        self.ignore = self.root / "empty-ignore"
        self.ignore.mkdir()
        # Inert provider-shaped token: synthetic, never sent to any API.
        self.fake = "ghp_" + "aB3dE5gH7jK9mN2pQ4sT6vW8xY0zC1fR3uV5"
        self.common = ["--config", str(HERE / "gitleaks.toml"),
                       "--gitleaks-ignore-path", str(self.ignore), "--ignore-gitleaks-allow",
                       "--redact=100", "--no-banner", "--no-color", "--timeout", "30",
                       "--max-target-megabytes", "10", "--max-decode-depth", "5",
                       "--max-archive-depth", "0"]

    def tearDown(self):
        self.tmp.cleanup()

    def run_scan(self, mode="dir", extra=()):
        source = self.snapshot if mode == "dir" else self.target / ".git"
        run = subprocess.run([BIN, mode, str(source), *self.common, *extra],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=45)
        self.assertNotIn(self.fake, run.stdout + run.stderr, "redaction must cover all captured output")
        return run

    def git(self, *args):
        env = os.environ.copy()
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_REPLACE_OBJECTS="1")
        return subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull, "-C", str(self.target), *args],
                              env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True).stdout.strip()

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", "synthetic fixture")
        return self.git("rev-parse", "HEAD")

    def test_clean_directory(self):
        (self.target / "README").write_text("ordinary documentation")
        self.assertEqual(self.run_scan().returncode, 0)

    def test_hidden_temp_token_allow_comment_and_pr_config_do_not_bypass(self):
        hidden = self.target / "temp/.hidden"
        hidden.mkdir(parents=True)
        (hidden / ".artifact").write_text(self.fake + " # gitleaks:allow\n")
        (self.target / ".gitleaks.toml").write_text('[allowlist]\npaths = [".*"]\n')
        self.assertEqual(self.run_scan().returncode, 1)

    def test_pr_ignore_file_does_not_bypass(self):
        (self.target / "token.txt").write_text(self.fake)
        report = self.root / "redacted.json"
        self.assertEqual(self.run_scan(extra=("--report-format", "json", "--report-path", str(report))).returncode, 1)
        findings = json.loads(report.read_text())
        self.assertNotIn(self.fake, report.read_text())
        (self.target / ".gitleaksignore").write_text("\n".join(f["Fingerprint"] for f in findings))
        self.assertEqual(self.run_scan().returncode, 1)

    def test_lockfiles_and_svg_are_not_globally_excluded(self):
        for name in ("package-lock.json", "image.svg", ".gitleaks.toml"):
            with self.subTest(name=name):
                path = self.target / name
                path.write_text(self.fake)
                self.assertEqual(self.run_scan().returncode, 1)
                path.unlink()

    def test_token_deleted_in_later_commit_is_found_in_history(self):
        self.git("init", "--template=", "--initial-branch=main")
        self.git("config", "user.name", "Synthetic fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.target / "README").write_text("baseline")
        base = self.commit()
        (self.target / "deleted.txt").write_text(self.fake)
        self.commit()
        (self.target / "deleted.txt").unlink()
        head = self.commit()
        opts = "--full-history --no-ext-diff --no-textconv --diff-merges=separate " + base + ".." + head
        report = self.root / "history-redacted.json"
        self.assertEqual(self.run_scan("git", ("--log-opts", opts, "--report-format", "json",
                                              "--report-path", str(report))).returncode, 1)
        findings = json.loads(report.read_text())
        self.assertNotIn(self.fake, report.read_text())
        # Even an exact working-tree root ignore must not influence the history scan.
        (self.target / ".gitleaksignore").write_text("\n".join(f["Fingerprint"] for f in findings))
        self.assertEqual(self.run_scan("git", ("--log-opts", opts)).returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
