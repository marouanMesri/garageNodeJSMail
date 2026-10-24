#!/usr/bin/env python3
"""Trusted, synthetic fixtures only; creates disposable repos beside this file."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("trusted_scanner", HERE / "scan_payloads.py")
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class Rules(unittest.TestCase):
    def test_opaque_asset_and_font_format(self):
        data = ("require" + "('inert-fixture');").encode()
        self.assertIn("hidden-executable-asset", dict(scanner.scan_bytes("public/fonts/sample.llf", data)))
        self.assertIn("invalid-font-header", dict(scanner.scan_bytes("public/fonts/sample.woff2", data)))
        self.assertEqual(scanner.scan_bytes("font.woff2", b"wOF2\x00inert"), [])
        self.assertIn("f831f23d591a496c5d3ea5ea6f12976c52e9de017c1a55e3d11684523717bdc2", scanner.KNOWN_BAD_SHA256)

    def test_known_hash_checked_without_real_malware_fixture(self):
        data = b"ordinary inert fixture"
        digest = hashlib.sha256(data).hexdigest()
        scanner.KNOWN_BAD_SHA256.add(digest)
        try:
            self.assertIn("known-malicious-sha256", dict(scanner.scan_bytes("opaque", data)))
        finally:
            scanner.KNOWN_BAD_SHA256.remove(digest)

    def test_exact_lifecycle_exception_changes_with_one_byte_or_path(self):
        text = json.dumps({"scripts": {"prebuild": "echo audited"}})
        digest = hashlib.sha256(text.encode()).hexdigest()
        policy = scanner.Exceptions([{"kind": "payload", "rule": "review-lifecycle-prebuild", "path": "package.json",
            "sha256": digest, "command": "echo audited", "reason": "Synthetic test"}])
        self.assertTrue(policy.allows("payload", "review-lifecycle-prebuild", "package.json", digest, text))
        self.assertFalse(policy.allows("payload", "review-lifecycle-prebuild", "other/package.json", digest, text))
        self.assertFalse(policy.allows("payload", "review-lifecycle-prebuild", "package.json", hashlib.sha256((text + " ").encode()).hexdigest(), text + " "))
        self.assertFalse(policy.allows("payload", "review-lifecycle-prebuild", "package.json", digest, json.dumps({"scripts": {"prebuild": "echo changed"}})))

    def test_no_exception_for_known_malware_or_control_changes(self):
        for rule in ["known-malicious-sha256", "protected-control-change", "hidden-executable-asset"]:
            with self.assertRaises(ValueError):
                scanner.Exceptions([{"kind": "payload", "rule": rule, "path": "file", "sha256": "a" * 64, "reason": "inert"}])
    def test_clean_config(self):
        self.assertEqual(scanner.scan_text("temp/.hidden/postcss.config.mjs", "export default {plugins: {}}"), [])

    def test_known_indicators_are_inert_data(self):
        # Construct individual inert indicators; never an actual malware payload.
        examples = ["global" + "['!'] = '10'", "Tgw" + "(2509)", "String.fromCharCode" + "(127)"]
        for example in examples:
            with self.subTest(example=example):
                self.assertTrue(scanner.scan_text("temp/.cache/opaque", example))

    def test_config_process_primitive_and_obfuscated_line(self):
        text = "import x from 'node:" + "child_process'\n" + " " * 1201 + "function() {}"
        rules = dict(scanner.scan_text(".cache/tailwind.config.cts", text))
        self.assertIn("config-process-execution", rules)
        self.assertIn("config-long-obfuscated-line", rules)

    def test_hidden_arbitrary_extension_and_encoded_execution(self):
        text = "eval" + "(atob('inert'))"
        self.assertIn("encoded-eval", dict(scanner.scan_text("temp/.hidden/.artifact", text)))

    def test_lifecycle_requires_review(self):
        data = json.dumps({"scripts": {"postinstall": "echo harmless-but-executable"}})
        self.assertIn("review-lifecycle-postinstall", dict(scanner.scan_text("temp/a/package.json", data)))

    def test_invalid_manifest_fails(self):
        for text in ("{} trailing", "[]", '{"scripts": []}'):
            self.assertIn("invalid-package-json", dict(scanner.scan_text("package.json", text)))

    def test_json_output_has_no_source_or_workflow_command(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            scanner.emit("finding", path="x\n::error::untrusted", rule="example")
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(out.getvalue())["path"], "x\n::error::untrusted")

    def test_paths_cannot_escape_export_or_create_git_metadata(self):
        for path in ("../x", "/x", "a//b", "a/./b", "a/.git/config", "a\\b", ""):
            self.assertFalse(scanner.safe_name(path), path)
        self.assertTrue(scanner.safe_name("temp/.hidden/file"))

    def test_no_global_gitleaks_directory_bypasses(self):
        config = tomllib.loads((HERE / "gitleaks.toml").read_text())
        self.assertEqual(config["allowlist"]["paths"], [r"(?:^|/)\.git(?:/|$)"])
        self.assertGreater(len(config["rules"]), 100)

    def test_all_recognized_codeowners_locations_are_protected(self):
        for path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
            self.assertTrue(scanner.protected_name(path))
        self.assertFalse(scanner.protected_name("CODEOWNERS.example"))


class GitObjects(unittest.TestCase):
    def test_oversize_arbitrary_extension_is_not_silently_clean(self):
        self.write("opaque.data", "x" * 101)
        previous = scanner.MAX_BYTES
        try:
            scanner.MAX_BYTES = 100
            stats, _ = self.audit(self.commit())
        finally:
            scanner.MAX_BYTES = previous
        self.assertGreater(stats["findings"], 0)

    def test_kit_and_its_fixtures_remain_scannable(self):
        for source in HERE.iterdir():
            if source.is_file():
                self.write(".github/security/" + source.name, source.read_text())
        self.base = self.commit()
        stats, events = self.audit(self.base)
        self.assertEqual(stats["findings"], 0, [(e.get("rule"), e.get("path")) for e in events if e["kind"] == "finding"])

    def test_intermediate_texts_and_pr_ignores_are_streamed(self):
        self.write("ignored/data.txt", "first synthetic marker")
        self.write(".gitignore", "ignored/\n")
        self.git("add", "--force", "ignored/data.txt")
        self.commit()
        (self.repo / "ignored/data.txt").unlink()
        head = self.commit()
        stream = self.root / "all-text.txt"
        stats, _ = self.audit(head, secret_input=stream)
        self.assertIn("first synthetic marker", stream.read_text())
        mapping = json.loads(stream.with_suffix(".map.json").read_text())
        self.assertTrue(any(row["path"] == "ignored/data.txt" for row in mapping))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="test-fixture-", dir=HERE)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "--template=", "--initial-branch=main")
        self.git("config", "user.name", "Synthetic fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.write("README", "synthetic baseline\n")
        self.base = self.commit()

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        run = subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull, "-C", str(self.repo), *args],
                             env=scanner.git_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return run.stdout.decode().strip()

    def write(self, name, text):
        p = self.repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", "synthetic fixture")
        return self.git("rev-parse", "HEAD")

    def audit(self, head, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            stats = scanner.audit(scanner.Repository(self.repo), self.base, head, **kwargs)
        return stats, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_clean_export_has_no_execute_bits(self):
        self.write("temp/.hidden/config", "plain data\n")
        head = self.commit()
        stats, _ = self.audit(head, export=self.root / "snapshot")
        self.assertEqual(stats["findings"], 0)
        target = self.root / "snapshot/temp/.hidden/config"
        self.assertEqual(target.read_text(), "plain data\n")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.root / "snapshot/.git").exists())

    def test_deleted_intermediate_payload_is_found_without_execution(self):
        self.write("temp/.cache/.opaque", "Tgw" + "(2509)")
        infected = self.commit()
        (self.repo / "temp/.cache/.opaque").unlink()
        head = self.commit()
        stats, events = self.audit(head)
        self.assertGreater(stats["findings"], 0)
        self.assertTrue(any(e.get("commit") == infected for e in events))

    def test_pr_scanner_and_config_replacements_cannot_disable_base_scanner(self):
        sentinel = self.root / "MUST_NOT_EXIST"
        self.write(".github/security/scan_payloads.py", "raise SystemExit(0)\n")
        self.write(".gitleaks.toml", 'title = "PR config must not be loaded"')
        self.write(".github/security/gitleaks.toml", 'title = "modified control"')
        self.write(".github/workflows/security.yml", "# disable all jobs")
        self.write("package.json", json.dumps({"scripts": {"postinstall": "touch " + str(sentinel)}}))
        head = self.commit()
        stats, events = self.audit(head, protect_controls=True)
        self.assertGreater(stats["findings"], 0)
        self.assertTrue(any(e.get("rule") == "protected-control-change" for e in events))
        self.assertFalse(sentinel.exists())

    def test_symlink_is_not_followed_or_exported(self):
        os.symlink("/etc/passwd", self.repo / "link")
        head = self.commit()
        stats, events = self.audit(head, export=self.root / "snapshot")
        self.assertGreater(stats["findings"], 0)
        self.assertTrue(any(e.get("rule") == "unsupported-link-or-submodule" for e in events))
        self.assertFalse((self.root / "snapshot/link").exists())

    def test_binary_and_large_config_gaps_are_visible_and_blocked(self):
        self.write("tailwind.config.js", "x" * 101)
        (self.repo / "postcss.config.js").write_bytes(b"\x00binary")
        head = self.commit()
        previous = scanner.MAX_BYTES
        try:
            scanner.MAX_BYTES = 100
            stats, _ = self.audit(head)
        finally:
            scanner.MAX_BYTES = previous
        self.assertEqual(stats["coverage_gaps"], 2)
        self.assertEqual(stats["findings"], 2)

    def test_old_symlink_is_not_hidden_by_identical_regular_file_blob(self):
        os.symlink(".target", self.repo / "same-bytes")
        self.commit()
        (self.repo / "same-bytes").unlink()
        self.write("same-bytes", ".target")
        stats, events = self.audit(self.commit())
        self.assertGreater(stats["findings"], 0)
        self.assertTrue(any(e.get("rule") == "unsupported-link-or-submodule" for e in events))

    def test_utf16_indicator_is_detected(self):
        (self.repo / "hidden").write_bytes(("Tgw" + "(2509)").encode("utf-16"))
        stats, _ = self.audit(self.commit())
        self.assertGreater(stats["findings"], 0)

    def test_commit_budget_fails_closed(self):
        self.write("second", "data")
        head = self.commit()
        previous = scanner.MAX_COMMITS
        try:
            scanner.MAX_COMMITS = 0
            with self.assertRaisesRegex(ValueError, "commit-budget"):
                self.audit(head)
        finally:
            scanner.MAX_COMMITS = previous

    def test_existing_destination_cannot_be_used(self):
        dest = self.root / "existing"
        dest.mkdir()
        with self.assertRaises(FileExistsError):
            self.audit(self.base, export=dest)

    def test_short_or_option_like_revision_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "full-commit-sha"):
            scanner.audit(scanner.Repository(self.repo), self.base, "--all")

    def test_control_change_then_revert_is_still_blocked(self):
        self.write(".github/workflows/other.yml", "# inert control change")
        self.commit()
        (self.repo / ".github/workflows/other.yml").unlink()
        head = self.commit()
        stats, events = self.audit(head, protect_controls=True)
        self.assertGreater(stats["findings"], 0)
        self.assertTrue(any(e.get("rule") == "protected-control-change" for e in events))

    def test_merge_commit_and_side_branch_history_are_scanned(self):
        self.git("checkout", "-b", "side")
        self.write("temp/.hidden/side", "Tgw" + "(2509)")
        infected = self.commit()
        (self.repo / "temp/.hidden/side").unlink()
        self.commit()
        self.git("checkout", "main")
        self.write("main-data", "inert")
        self.commit()
        self.git("merge", "--no-ff", "side", "-m", "synthetic merge")
        stats, events = self.audit(self.git("rev-parse", "HEAD"))
        self.assertGreater(stats["findings"], 0)
        self.assertTrue(any(e.get("commit") == infected for e in events))

    def test_submodule_object_is_blocked_without_fetching(self):
        self.git("update-index", "--add", "--cacheinfo", "160000," + self.base + ",module")
        self.git("commit", "--quiet", "-m", "synthetic gitlink")
        stats, events = self.audit(self.git("rev-parse", "HEAD"))
        self.assertGreater(stats["findings"], 0)
        self.assertTrue(any(e.get("rule") == "unsupported-link-or-submodule" for e in events))

    def test_merging_unchanged_trusted_controls_from_base_is_allowed(self):
        self.git("checkout", "-b", "feature")
        self.write("feature-data", "inert")
        self.commit()
        self.git("checkout", "main")
        self.write(".github/workflows/security.yml", "# trusted base control")
        self.base = self.commit()
        self.git("checkout", "feature")
        self.git("merge", "--no-ff", "main", "-m", "bring trusted base up to date")
        stats, events = self.audit(self.git("rev-parse", "HEAD"), protect_controls=True)
        self.assertEqual(stats["findings"], 0)
        self.assertFalse(any(e.get("rule") == "protected-control-change" for e in events))


if __name__ == "__main__":
    unittest.main(verbosity=2)
