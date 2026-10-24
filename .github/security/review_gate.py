#!/usr/bin/env python3
"""Read-only owner-review policy. Trusted base code; no PR code execution.

This is a point-in-time check, not a GitHub-side continuously enforced review rule.
"""
import argparse
import json
import os
import re
import sys
import urllib.request

OWNER = "marouanMesri"
MAX_REVIEW_PAGES = 10


def decision(pr: dict, reviews: list[dict], head: str, base: str) -> tuple[bool, str]:
    if pr.get("state") != "open":
        return False, "pull-request-not-open"
    if pr.get("head", {}).get("sha") != head or pr.get("base", {}).get("sha") != base:
        return False, "stale-run-head-or-base-moved"
    if pr.get("user", {}).get("login", "").casefold() == OWNER.casefold():
        return True, "owner-authored-automatic-controls-required"
    formal = [r for r in reviews if r.get("user", {}).get("login", "").casefold() == OWNER.casefold()
              and r.get("state") in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}]
    if not formal:
        return False, "owner-approval-required"
    latest = max(formal, key=lambda r: int(r["id"]))
    if latest.get("state") != "APPROVED":
        return False, "latest-owner-review-not-approved"
    if latest.get("commit_id") != head:
        return False, "owner-approval-is-for-another-head"
    return True, "owner-approved-current-head"


class Client:
    def __init__(self, repository: str, number: int, token: str):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or number < 1:
            raise ValueError("invalid-repository-or-pr")
        self.path = f"https://api.github.com/repos/{repository}/pulls/{number}"
        self.token = token

    def get(self, suffix=""):
        request = urllib.request.Request(self.path + suffix, headers={
            "Accept": "application/vnd.github+json", "Authorization": "Bearer " + self.token,
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "trusted-security-review-gate",
        })
        with urllib.request.urlopen(request, timeout=20) as response:
            data = response.read(5_000_001)
            if len(data) > 5_000_000:
                raise ValueError("api-response-budget-exceeded")
            return json.loads(data)

    def reviews(self):
        reviews = []
        for page in range(1, MAX_REVIEW_PAGES + 1):
            batch = self.get(f"/reviews?per_page=100&page={page}")
            if not isinstance(batch, list):
                raise ValueError("invalid-review-response")
            reviews.extend(batch)
            if len(batch) < 100:
                return reviews
        raise ValueError("review-pagination-budget-exceeded")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--head", required=True)
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    try:
        if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (args.head, args.base)):
            raise ValueError("full-sha-required")
        client = Client(args.repository, args.pr, os.environ["REVIEW_TOKEN"])
        pr = client.get()
        owner_authored = pr.get("user", {}).get("login", "").casefold() == OWNER.casefold()
        reviews = [] if owner_authored else client.reviews()
        # Re-read current metadata after pagination to catch a concurrent push.
        current = client.get()
        if current.get("user", {}).get("login") != pr.get("user", {}).get("login"):
            raise ValueError("author-changed")
        allowed, reason = decision(current, reviews, args.head, args.base)
        print(json.dumps({"review_gate": "pass" if allowed else "fail", "reason": reason}))
        return 0 if allowed else 1
    except Exception:
        # Never include response bodies, tokens, PR text or API exception URLs in logs.
        print(json.dumps({"review_gate": "error", "reason": "review-api-or-policy-validation-failed"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
