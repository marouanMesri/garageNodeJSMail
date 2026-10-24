#!/usr/bin/env python3
"""Pure review-policy tests. No network, credentials or live reviews."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("trusted_review_gate", HERE / "review_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
HEAD = "a" * 40
BASE = "b" * 40


class ReviewPolicy(unittest.TestCase):
    def pr(self, author="contributor"):
        return {"state": "open", "user": {"login": author}, "head": {"sha": HEAD}, "base": {"sha": BASE}}

    def review(self, state="APPROVED", commit=HEAD, author="marouanMesri", number=1):
        return {"id": number, "state": state, "commit_id": commit, "user": {"login": author}}

    def test_owner_can_work_alone_without_human_approval(self):
        self.assertTrue(gate.decision(self.pr("MAROUANMESRI"), [], HEAD, BASE)[0])

    def test_other_author_needs_owner_approval(self):
        self.assertFalse(gate.decision(self.pr(), [], HEAD, BASE)[0])
        self.assertTrue(gate.decision(self.pr(), [self.review()], HEAD, BASE)[0])

    def test_other_reviewer_cannot_substitute_for_owner(self):
        self.assertFalse(gate.decision(self.pr(), [self.review(author="someone-else")], HEAD, BASE)[0])

    def test_old_head_approval_is_not_accepted(self):
        self.assertFalse(gate.decision(self.pr(), [self.review(commit="c" * 40)], HEAD, BASE)[0])

    def test_dismissed_or_changes_requested_override_approval(self):
        for state in ("DISMISSED", "CHANGES_REQUESTED"):
            with self.subTest(state=state):
                reviews = [self.review(), self.review(state=state, number=2)]
                self.assertFalse(gate.decision(self.pr(), reviews, HEAD, BASE)[0])

    def test_comment_does_not_cancel_formal_approval(self):
        reviews = [self.review(), self.review(state="COMMENTED", number=2)]
        self.assertTrue(gate.decision(self.pr(), reviews, HEAD, BASE)[0])

    def test_metadata_head_or_base_moved_is_rejected_even_for_owner(self):
        for field in ("head", "base"):
            pr = self.pr("marouanMesri")
            pr[field]["sha"] = "d" * 40
            self.assertFalse(gate.decision(pr, [], HEAD, BASE)[0])

    def test_closed_pr_is_rejected(self):
        pr = self.pr("marouanMesri")
        pr["state"] = "closed"
        self.assertFalse(gate.decision(pr, [], HEAD, BASE)[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
