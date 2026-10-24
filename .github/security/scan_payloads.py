#!/usr/bin/env python3
"""Read Git blobs as data. No imports, checkout, filters or execution from the target."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

MAX_BYTES = 50_000_000
MAX_COMMITS = 200
MAX_ENTRIES = 200_000
MAX_TOTAL_BYTES = 1_000_000_000
KNOWN_BAD_SHA256 = {"f831f23d591a496c5d3ea5ea6f12976c52e9de017c1a55e3d11684523717bdc2"}
PROPAGATION = {"branch_structure.json", "config.bat", "temp_auto_push.bat", "temp_interactive_push.bat"}
SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
JS = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx"}

# Signatures, not a runnable payload. Never print matched source text.
RULES = {
    "polin-global-marker": re.compile(r"global\s*\[\s*['\"]!['\"]\s*\]\s*=\s*['\"]10['\"]"),
    "polin-stage-call": re.compile(r"\bTgw\s*\(\s*2509\s*\)"),
    "polin-decoder-delimiter": re.compile(r"String\s*\.\s*fromCharCode\s*\(\s*127\s*\)"),
    "global-require-rebind": re.compile(r"(?:global|globalThis)\s*\[[^\]\n]{1,100}\]\s*=\s*require\b"),
    "obfuscated-decoder": re.compile(r"\b(?:var|let|const)\s+_\$_\w+\s*=\s*\(?\s*function\b"),
    "download-pipe-shell": re.compile(r"\b(?:curl|wget)\b[^\n]{0,500}\|\s*(?:ba|z|da)?sh\b"),
    "encoded-eval": re.compile(r"\b(?:eval|Function)\s*\(\s*(?:atob\s*\(|Buffer\s*\.\s*from\s*\()"),
}
SHELL_IMPORT = re.compile(r"(?:require\s*\(\s*['\"](?:node:)?child_process['\"]|from\s*['\"](?:node:)?child_process['\"]|import\s*\(\s*['\"](?:node:)?child_process['\"])")
DYNAMIC = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")
SENSITIVE = re.compile(r"(?:\.ssh[/\\]|\.aws[/\\]|\.npmrc\b|Login Data|login\.keychain|Cookies\b)")
NETWORK = re.compile(r"\b(?:fetch|https?\s*\.\s*(?:request|get)|axios\s*\.\s*post)\s*\(")


class Exceptions:
    """Trusted base-only, exact rule/path/original-byte-hash decisions; no PR ignores."""
    def __init__(self, rows=()):
        self.rows = []
        allowed = {"download-pipe-shell", "sensitive-path-with-network", "config-process-execution", "config-dynamic-execution"}
        for row in rows:
            if not isinstance(row, dict) or set(row) - {"kind", "rule", "path", "sha256", "reason", "command"}:
                raise ValueError("invalid-exception-schema")
            if row.get("kind") not in {"payload", "secret"} or not isinstance(row.get("path"), str) or not safe_name(row["path"]):
                raise ValueError("invalid-exception-kind-or-path")
            if not isinstance(row.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) or not isinstance(row.get("reason"), str) or not row["reason"].strip():
                raise ValueError("exception-needs-hash-and-review-reason")
            rule = row.get("rule", "")
            if not isinstance(rule, str) or not re.fullmatch(r"[a-z0-9-]+", rule):
                raise ValueError("invalid-exception-rule")
            if not rule or (row["kind"] == "payload" and rule not in allowed and not rule.startswith("review-lifecycle-")):
                raise ValueError("nonwaivable-payload-rule")
            if rule.startswith("review-lifecycle-") and not isinstance(row.get("command"), str):
                raise ValueError("lifecycle-exception-needs-exact-command")
            self.rows.append(dict(row))

    @classmethod
    def trusted(cls):
        path = Path(__file__).resolve().parent / "policy_exceptions.json"
        value = json.loads(path.read_text())
        if set(value) != {"version", "exceptions"} or value["version"] != 1 or not isinstance(value["exceptions"], list):
            raise ValueError("invalid-exception-file")
        return cls(value["exceptions"])

    def allows(self, kind, rule, path, digest, text=""):
        for row in self.rows:
            if (row["kind"], row["rule"], row["path"], row["sha256"]) != (kind, rule, path, digest):
                continue
            if rule.startswith("review-lifecycle-"):
                try:
                    command = json.loads(text)["scripts"][rule.removeprefix("review-lifecycle-")]
                except (ValueError, KeyError, TypeError):
                    continue
                if command != row["command"]:
                    continue
            return True
        return False


def scan_bytes(name, data):
    result = []
    if hashlib.sha256(data).hexdigest() in KNOWN_BAD_SHA256:
        result.append(("known-malicious-sha256", 1))
    suffix = PurePosixPath(name).suffix.lower()
    headers = {".woff": (b"wOFF",), ".woff2": (b"wOF2",), ".ttf": (b"\0\1\0\0", b"OTTO", b"ttcf"), ".otf": (b"OTTO",)}
    if suffix in headers and not data.startswith(headers[suffix]):
        result.append(("invalid-font-header", 1))
    if suffix == ".eot" and (len(data) < 36 or int.from_bytes(data[:4], "little") != len(data) or data[34:36] != b"LP"):
        result.append(("invalid-font-header", 1))
    if suffix in {*headers, ".llf", ".eot"} and re.search(rb"require\s*\(|child_process|eval\s*\(|var\s+_\$_|global\[", data):
        result.append(("hidden-executable-asset", 1))
    if PurePosixPath(name).name in PROPAGATION:
        result.append(("propagation-artifact", 1))
    return result


def emit(kind: str, **fields) -> None:
    # JSON escaping prevents filenames/newlines from becoming workflow commands.
    print(json.dumps({"kind": kind, **fields}, ensure_ascii=True), flush=True)


def executable_config(name: str) -> bool:
    p = PurePosixPath(name)
    return p.suffix.lower() in JS and (
        ".config." in p.name.lower() or p.name.lower().startswith(".pnp.")
    )


def scan_text(name: str, text: str) -> list[tuple[str, int]]:
    findings = []
    for rule, pattern in RULES.items():
        match = pattern.search(text)
        if match:
            findings.append((rule, text.count("\n", 0, match.start()) + 1))
    if executable_config(name):
        for rule, pattern in (("config-process-execution", SHELL_IMPORT), ("config-dynamic-execution", DYNAMIC)):
            match = pattern.search(text)
            if match:
                findings.append((rule, text.count("\n", 0, match.start()) + 1))
        for line, value in enumerate(text.splitlines(), 1):
            if len(value) > 1200 and re.search(r"function\s*\(|fromCharCode|global\s*\[", value):
                findings.append(("config-long-obfuscated-line", line))
                break
    if SENSITIVE.search(text) and NETWORK.search(text):
        findings.append(("sensitive-path-with-network", 1))
    if PurePosixPath(name).name == ".gitignore" and any(line.strip() in PROPAGATION for line in text.splitlines()):
        findings.append(("hidden-propagation-artifact", 1))
    if name.endswith("/tasks.json") and (".vscode/" in name or ".cursor/" in name) and "folderOpen" in text:
        findings.append(("editor-folder-open-task", 1))
    if PurePosixPath(name).name == "package.json":
        try:
            scripts = json.loads(text).get("scripts", {})
            if not isinstance(scripts, dict):
                raise ValueError
            for key in ("preinstall", "install", "postinstall", "prepare", "prebuild", "postbuild"):
                if scripts.get(key):
                    findings.append(("review-lifecycle-" + key, 1))
        except (ValueError, AttributeError):
            findings.append(("invalid-package-json", 1))
    return findings


def safe_name(name: str) -> bool:
    parts = name.split("/")
    return bool(name) and not name.startswith("/") and all(
        part not in {"", ".", "..", ".git"} for part in parts
    ) and "\\" not in name


def protected_name(name: str) -> bool:
    return name.startswith((".github/security/", ".github/workflows/")) or name in {
        ".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"
    }


def git_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key)
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0")
    return env


class Repository:
    def __init__(self, path: Path):
        self.path = path.resolve()
        self.prefix = ["git", "-c", "core.hooksPath=" + os.devnull,
                       "-c", "core.attributesFile=" + os.devnull,
                       "-c", "diff.external=", "-C", str(self.path)]

    def git(self, *args: str) -> bytes:
        run = subprocess.run(self.prefix + list(args), env=git_env(), stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=90)
        if run.returncode:
            # Do not leak git errors containing file contents or remote URLs.
            raise ValueError("git-command-failed: " + args[0])
        return run.stdout

    def revisions(self, base: str, head: str) -> list[str]:
        if not SHA.fullmatch(base) or not SHA.fullmatch(head):
            raise ValueError("full-commit-sha-required")
        if self.git("rev-parse", "--is-shallow-repository").strip() != b"false":
            raise ValueError("shallow-history-not-supported")
        for ref in (base, head):
            if self.git("cat-file", "-t", ref).strip() != b"commit":
                raise ValueError("commit-required")
        refs = self.git("rev-list", "--max-count=" + str(MAX_COMMITS + 1), base + ".." + head).decode().splitlines()
        if len(refs) > MAX_COMMITS:
            raise ValueError("commit-budget-exceeded")
        # Head is always scanned, including PRs containing only already-known commits.
        return list(dict.fromkeys([head] + refs))

    def entries(self, ref: str):
        raw = self.git("ls-tree", "-r", "-l", "-z", ref)
        entries = raw.split(b"\0")
        if len(entries) - 1 > MAX_ENTRIES:
            raise ValueError("tree-budget-exceeded")
        for item in entries:
            if not item:
                continue
            meta, raw_name = item.split(b"\t", 1)
            mode, kind, oid, size = meta.split()
            name = raw_name.decode("utf-8", errors="strict")
            if not safe_name(name):
                raise ValueError("unsafe-tree-path")
            yield mode.decode(), kind.decode(), oid.decode(), int(size) if size != b"-" else 0, name


def audit(repo: Repository, base: str, head: str, export: Path | None = None,
          protect_controls: bool = False, secret_input: Path | None = None,
          exceptions=None) -> dict[str, int]:
    exceptions = Exceptions.trusted() if exceptions is None else exceptions
    revisions = repo.revisions(base, head)
    if export is not None:
        export = export.absolute()
        # Destination must be fresh; no pre-existing symlinks or PR-controlled tree.
        export.mkdir(parents=False, exist_ok=False)
    stats = {"revisions": len(revisions), "text_blobs": 0, "findings": 0,
             "coverage_gaps": 0, "entries": 0, "bytes": 0, "exceptions": 0}
    secret_stream = None
    secret_map = []
    next_line = 1
    if secret_input is not None:
        secret_stream = secret_input.open("xb")
        secret_input.chmod(0o600)
    if protect_controls:
        # Compare resulting controls with the trusted base, so a merge that only
        # imports an unchanged base control is allowed. Earlier tampering still fails.
        base_controls = {name: (mode, oid) for mode, kind, oid, size, name in repo.entries(base)
                         if protected_name(name)}
        new_refs = repo.git("rev-list", base + ".." + head).decode().splitlines()
        for ref in new_refs:
            controls = {name: (mode, oid) for mode, kind, oid, size, name in repo.entries(ref)
                        if protected_name(name)}
            changed = repo.git("diff-tree", "--root", "-m", "--no-commit-id", "--name-only", "-r", "-z", ref)
            for raw_name in changed.split(b"\0"):
                name = raw_name.decode("utf-8", errors="strict")
                if protected_name(name) and controls.get(name) != base_controls.get(name):
                    emit("finding", rule="protected-control-change", path=name, commit=ref)
                    stats["findings"] += 1
    seen = set()
    reader = subprocess.Popen(repo.prefix + ["cat-file", "--batch"], env=git_env(),
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        for ref in revisions:
            for mode, kind, oid, size, name in repo.entries(ref):
                # A symlink and a regular file can share blob bytes: mode is semantic.
                key = (name, oid, mode, kind)
                if key in seen:
                    continue
                seen.add(key)
                stats["entries"] += 1
                stats["bytes"] += size
                if stats["entries"] > MAX_ENTRIES or stats["bytes"] > MAX_TOTAL_BYTES:
                    raise ValueError("scan-budget-exceeded")
                if mode not in {"100644", "100755"} or kind != "blob":
                    emit("finding", rule="unsupported-link-or-submodule", path=name, commit=ref)
                    stats["findings"] += 1
                    continue
                if size > MAX_BYTES:
                    emit("coverage-gap", reason="oversize", path=name, commit=ref, bytes=size)
                    stats["coverage_gaps"] += 1
                    # A huge executable config is a bypass attempt, not a clean scan.
                    stats["findings"] += 1
                    continue
                reader.stdin.write((oid + "\n").encode("ascii"))
                reader.stdin.flush()
                header = reader.stdout.readline().split()
                if len(header) != 3 or header[1] != b"blob" or int(header[2]) != size:
                    raise ValueError("invalid-blob-header")
                data = reader.stdout.read(size)
                if len(data) != size or reader.stdout.read(1) != b"\n":
                    raise ValueError("incomplete-blob")
                digest = hashlib.sha256(data).hexdigest()
                for rule, line in scan_bytes(name, data):
                    emit("finding", rule=rule, path=name, line=line, commit=ref)
                    stats["findings"] += 1
                if export is not None and ref == head:
                    target = export / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    # Executable bits intentionally discarded: exported files are data.
                    with target.open("xb") as output:
                        output.write(data)
                    target.chmod(0o600)
                try:
                    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
                        text = data.decode("utf-16")
                    else:
                        if b"\0" in data:
                            raise UnicodeError
                        text = data.decode("utf-8-sig")
                except UnicodeError:
                    emit("coverage-gap", reason="binary-or-unsupported-encoding", path=name, commit=ref)
                    stats["coverage_gaps"] += 1
                    if executable_config(name):
                        stats["findings"] += 1
                    continue
                stats["text_blobs"] += 1
                if secret_stream is not None:
                    encoded = (text.rstrip("\n") + "\n").encode("utf-8")
                    lines = encoded.count(b"\n")
                    secret_stream.write(encoded)
                    secret_map.append({"start": next_line, "end": next_line + lines - 1,
                                       "path": name, "commit": ref, "sha256": digest})
                    next_line += lines
                for rule, line in scan_text(name, text):
                    if exceptions.allows("payload", rule, name, digest, text):
                        emit("audited-exception", rule=rule, path=name, commit=ref, sha256=digest)
                        stats["exceptions"] += 1
                        continue
                    emit("finding", rule=rule, path=name, line=line, commit=ref)
                    stats["findings"] += 1
    finally:
        if secret_stream is not None:
            secret_stream.close()
            secret_input.with_suffix(".map.json").write_text(json.dumps(secret_map))
        reader.stdin.close()
        reader.stdout.close()
        try:
            reader.wait(timeout=5)
        except subprocess.TimeoutExpired:
            reader.kill()
            reader.wait()
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--export-head", type=Path)
    parser.add_argument("--protect-controls", action="store_true")
    parser.add_argument("--secret-input", type=Path)
    args = parser.parse_args()
    try:
        stats = audit(Repository(args.repo), args.base, args.head, args.export_head, args.protect_controls, args.secret_input)
        emit("summary", **stats)
        return 1 if stats["findings"] else 0
    except (OSError, ValueError, subprocess.SubprocessError):
        emit("error", reason="incomplete-scan-see-trusted-tests-and-budgets")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
