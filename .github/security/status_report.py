#!/usr/bin/env python3
"""Trusted HEAD status reporting and review refresh; no target code or artifacts."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import urllib.request
import urllib.error

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("trusted_review", HERE / "review_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
PAYLOAD = "security/payloads"
REVIEW = "security/owner-review"
MAX_OPEN_PRS = 100


class API:
    def __init__(self, repository, token):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("invalid-repository")
        self.repository, self.token = repository, token

    def request(self, suffix, body=None):
        request = urllib.request.Request("https://api.github.com/repos/" + self.repository + suffix,
            data=None if body is None else json.dumps(body).encode(), headers={
                "Accept": "application/vnd.github+json", "Authorization": "Bearer " + self.token,
                "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "trusted-head-security-status", "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=20) as response:
            data = response.read(5_000_001)
            if len(data) > 5_000_000:
                raise ValueError("api-budget")
            return json.loads(data)

    def status(self, head, context, state, reason):
        if not re.fullmatch(r"[0-9a-f]{40}", head) or context not in {PAYLOAD, REVIEW}:
            raise ValueError("invalid-status")
        self.request("/statuses/" + head, {"context": context, "state": state, "description": reason[:140]})

    def pulls(self):
        result = self.request("/pulls?state=open&per_page=100")
        if not isinstance(result, list) or len(result) >= MAX_OPEN_PRS:
            raise ValueError("open-pr-budget-reached")
        return result

    def reviews(self, number):
        rows = []
        for page in range(1, gate.MAX_REVIEW_PAGES + 1):
            batch = self.request(f"/pulls/{number}/reviews?per_page=100&page={page}")
            if not isinstance(batch, list):
                raise ValueError("invalid-review-list")
            rows.extend(batch)
            if len(batch) < 100:
                return rows
        raise ValueError("review-budget-reached")


def validate_pr(api, number, head, base):
    pr = api.request(f"/pulls/{number}")
    repository = api.request("")
    if (pr.get("state") != "open" or pr.get("head", {}).get("sha") != head
        or pr.get("base", {}).get("sha") != base or pr.get("base", {}).get("ref") != repository.get("default_branch")
        or pr.get("base", {}).get("repo", {}).get("full_name", "").casefold() != api.repository.casefold()):
        raise ValueError("stale-or-nondefault-pr")
    return pr


def publish_for_pr(api, pr, context, state, reason):
    """HEAD is mandatory; mirror to test-merge only if its tree is the scanned tree."""
    head = pr["head"]["sha"]
    targets = [(head, state, reason)]
    try:
        ref = api.request(f"/git/ref/pull/{int(pr['number'])}/merge")
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        ref = None
    # Some repositories do not expose pull refs through the refs endpoint;
    # the PR API's current test-merge SHA is also data, verified below.
    merge = ref["object"]["sha"] if ref else pr.get("merge_commit_sha")
    if merge:
        if not re.fullmatch(r"[0-9a-f]{40}", merge):
            raise ValueError("invalid-test-merge-sha")
        merged = api.request("/git/commits/" + merge)
        original = api.request("/git/commits/" + head)
        parents = {p["sha"] for p in merged["parents"]}
        same = merged["tree"]["sha"] == original["tree"]["sha"] and {head, pr["base"]["sha"]} <= parents
        targets.append((merge, state if same else "failure", reason if same else "update-branch-test-merge-tree-not-scanned"))
    for sha, result, message in targets:
        api.status(sha, context, result, message)


def report_payload(api, number, head, base, phase, result):
    if phase == "pending":
        api.status(head, PAYLOAD, "pending", "trusted-data-scan-running")
        api.status(head, REVIEW, "pending", "current-owner-review-not-yet-validated")
        pr = validate_pr(api, number, head, base)
        publish_for_pr(api, pr, PAYLOAD, "pending", "trusted-data-scan-running")
        publish_for_pr(api, pr, REVIEW, "pending", "current-owner-review-not-yet-validated")
        return
    try:
        pr = validate_pr(api, number, head, base)
        state = "success" if result == "success" else "failure"
        publish_for_pr(api, pr, PAYLOAD, state, "trusted-data-scan-" + state)
    except Exception:
        api.status(head, PAYLOAD, "failure", "stale-or-incomplete-security-run")
        raise


def refresh_reviews(api):
    pulls = api.pulls()
    repository = api.request("")
    grouped = {}
    for item in pulls:
        head = item["head"]["sha"]
        grouped.setdefault(head, []).append(item)
    for items in grouped.values():
        for item in items:
            publish_for_pr(api, item, REVIEW, "pending", "revalidating-current-owner-reviews")
    for head, items in grouped.items():
        allowed = True
        current_items = []
        try:
            for item in items:
                current = api.request(f"/pulls/{int(item['number'])}")
                base = item["base"]["sha"]
                owner = current.get("user", {}).get("login", "").casefold() == gate.OWNER.casefold()
                reviews = [] if owner else api.reviews(int(item["number"]))
                current = api.request(f"/pulls/{int(item['number'])}")
                if current.get("head", {}).get("sha") != head or current.get("base", {}).get("sha") != base:
                    raise ValueError("pr-moved-during-review-refresh")
                current_items.append(current)
                ok, _ = gate.decision(current, reviews, head, base)
                allowed = allowed and ok and current.get("base", {}).get("ref") == repository.get("default_branch")
            for current in current_items:
                publish_for_pr(api, current, REVIEW, "success" if allowed else "failure", "owner-review-current-head-" + ("accepted" if allowed else "required"))
        except Exception:
            api.status(head, REVIEW, "failure", "review-validation-incomplete")
            raise
    return len(grouped)


def validate_relay_event(api, event_name, payload):
    if event_name == "workflow_dispatch":
        return
    if event_name != "workflow_run":
        raise ValueError("unexpected-review-trigger")
    number = payload.get("workflow_run", {}).get("id")
    if not isinstance(number, int) or number < 1:
        raise ValueError("invalid-relay-run")
    run = api.request(f"/actions/runs/{number}")
    if run.get("event") != "pull_request_review" or run.get("path", "").split("@", 1)[0] != ".github/workflows/security-review-signal.yml":
        raise ValueError("unexpected-review-relay")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--event", type=Path)
    parser.add_argument("--pr", type=int)
    parser.add_argument("--head")
    parser.add_argument("--base")
    parser.add_argument("--phase", choices=["pending", "final"])
    parser.add_argument("--result", default="failure")
    args = parser.parse_args()
    try:
        api = API(args.repository, os.environ["STATUS_TOKEN"])
        if args.refresh:
            if args.event:
                validate_relay_event(api, os.environ["GITHUB_EVENT_NAME"], json.loads(args.event.read_text()))
            count = refresh_reviews(api)
            print(json.dumps({"review_heads_refreshed": count}))
        else:
            if not args.pr or not all(re.fullmatch(r"[0-9a-f]{40}", s or "") for s in [args.head, args.base]):
                raise ValueError("full-sha-and-pr-required")
            report_payload(api, args.pr, args.head, args.base, args.phase, args.result)
        return 0
    except Exception:
        print(json.dumps({"error": "trusted-status-reporting-incomplete"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
