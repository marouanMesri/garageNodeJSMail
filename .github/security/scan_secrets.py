#!/usr/bin/env python3
"""Scan trusted scanner's complete text stream with Gitleaks; no PR configuration."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("trusted_payload_scanner", HERE / "scan_payloads.py")
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def scan(binary, stream, config=None, exceptions=None):
    config = HERE / "gitleaks.toml" if config is None else config
    mapping = json.loads(stream.with_suffix(".map.json").read_text())
    policy = scanner.Exceptions.trusted() if exceptions is None else exceptions
    env = {k: v for k, v in os.environ.items() if k not in {"GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"}}
    with tempfile.TemporaryDirectory(prefix="trusted-secret-scan-", dir=stream.parent) as folder:
        report = Path(folder) / "redacted.json"
        ignore = Path(folder) / "empty-ignore"
        ignore.mkdir()
        with stream.open("rb") as source:
            run = subprocess.run([str(binary), "stdin", "--config", str(config),
                "--gitleaks-ignore-path", str(ignore), "--ignore-gitleaks-allow", "--redact=100",
                "--no-banner", "--no-color", "--max-decode-depth", "5", "--max-archive-depth", "0",
                "--timeout", "300", "--report-format", "json", "--report-path", str(report)],
                stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=HERE, timeout=330)
        if run.returncode not in {0, 1} or not report.exists():
            raise ValueError("gitleaks-incomplete")
        findings = json.loads(report.read_text())
        remaining = []
        waived = 0
        for item in findings:
            locations = [m for m in mapping if m["start"] <= item["StartLine"] <= m["end"]]
            if len(locations) != 1:
                raise ValueError("unmapped-secret-finding")
            location = locations[0]
            rule = item["RuleID"]
            # A generic regex may start in one blob and end in the next. An
            # exception for the first file must never waive bytes of another.
            single_blob = item.get("EndLine", item["StartLine"]) <= location["end"]
            if single_blob and policy.allows("secret", rule, location["path"], location["sha256"]):
                waived += 1
                continue
            remaining.append({"rule": rule, "path": location["path"], "commit": location["commit"],
                              "line": item["StartLine"] - location["start"] + 1, "cross_blob": not single_blob})
        if run.returncode == 1 and not findings:
            raise ValueError("gitleaks-failed-without-findings")
        # Never forward Match, Secret, stderr, or PR-controlled source excerpts.
        return {"text_records": len(mapping), "input_bytes": stream.stat().st_size,
                "findings": remaining, "audited_exceptions": waived}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = scan(args.binary.resolve(), args.input.resolve())
        print(json.dumps(result, ensure_ascii=True))
        return 1 if result["findings"] else 0
    except (OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({"error": "secret-scan-incomplete"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
