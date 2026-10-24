#!/usr/bin/env python3
"""In-memory API fixtures only: no GitHub writes or credentials."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("trusted_status", HERE / "status_report.py")
status = importlib.util.module_from_spec(spec)
spec.loader.exec_module(status)
HEAD, BASE = "a" * 40, "b" * 40


class FakeAPI:
    repository = "owner/repo"
    def __init__(self, author="contributor"):
        self.pr = {"number": 1, "state": "open", "head": {"sha": HEAD},
                   "base": {"sha": BASE, "ref": "main", "repo": {"full_name": self.repository}},
                   "user": {"login": author}}
        self.rows = []
        self.statuses = []
        self.merge_tree_same = None
        self.hide_merge_ref = False
    def request(self, path):
        if path == "": return {"default_branch": "main"}
        if path == "/pulls/1": return copy.deepcopy(self.pr)
        if path == "/actions/runs/1": return {"event": "pull_request_review", "path": ".github/workflows/security-review-signal.yml"}
        if path == "/git/ref/pull/1/merge": return None if self.merge_tree_same is None or self.hide_merge_ref else {"object": {"sha": "d" * 40}}
        if path == "/git/commits/" + HEAD: return {"tree": {"sha": "e" * 40}}
        if path == "/git/commits/" + "d" * 40:
            return {"tree": {"sha": "e" * 40 if self.merge_tree_same else "f" * 40}, "parents": [{"sha": HEAD}, {"sha": BASE}]}
        raise AssertionError("unexpected mocked API path")
    def pulls(self): return [copy.deepcopy(self.pr)]
    def reviews(self, number): return copy.deepcopy(self.rows)
    def status(self, head, context, state, reason): self.statuses.append((head, context, state))


class HeadStatuses(unittest.TestCase):
    def test_review_refresh_does_not_clobber_new_head_from_stale_list(self):
        class MovingAPI(FakeAPI):
            def pulls(self):
                old = copy.deepcopy(self.pr)
                self.pr["head"]["sha"] = "c" * 40
                return [old]
        api = MovingAPI("marouanMesri")
        with self.assertRaises(ValueError): status.refresh_reviews(api)
        self.assertTrue(all(row[0] == HEAD for row in api.statuses))
    def test_merge_status_only_succeeds_for_same_scanned_tree(self):
        api = FakeAPI()
        api.merge_tree_same = True
        status.report_payload(api, 1, HEAD, BASE, "final", "success")
        self.assertIn(("d" * 40, status.PAYLOAD, "success"), api.statuses)
        api.hide_merge_ref = True
        api.pr["merge_commit_sha"] = "d" * 40
        status.report_payload(api, 1, HEAD, BASE, "final", "success")
        self.assertEqual(api.statuses[-1], ("d" * 40, status.PAYLOAD, "success"))
        api.merge_tree_same = False
        status.report_payload(api, 1, HEAD, BASE, "final", "success")
        self.assertEqual(api.statuses[-1], ("d" * 40, status.PAYLOAD, "failure"))
    def test_explicit_head_is_used_never_base(self):
        api = FakeAPI()
        status.report_payload(api, 1, HEAD, BASE, "pending", "success")
        status.report_payload(api, 1, HEAD, BASE, "final", "success")
        self.assertTrue(all(row[0] == HEAD for row in api.statuses))
        self.assertIn((HEAD, status.PAYLOAD, "success"), api.statuses)
    def test_failure_and_stale_runs_do_not_publish_success(self):
        api = FakeAPI()
        status.report_payload(api, 1, HEAD, BASE, "final", "cancelled")
        self.assertEqual(api.statuses[-1][2], "failure")
        api.pr["head"]["sha"] = "c" * 40
        with self.assertRaises(ValueError): status.report_payload(api, 1, HEAD, BASE, "final", "success")
        self.assertEqual(api.statuses[-1], (HEAD, status.PAYLOAD, "failure"))
    def test_approval_then_dismissal_recomputes_same_head(self):
        api = FakeAPI()
        status.refresh_reviews(api)
        self.assertEqual(api.statuses[-1][2], "failure")
        api.rows = [{"id": 1, "state": "APPROVED", "commit_id": HEAD, "user": {"login": "marouanMesri"}}]
        status.refresh_reviews(api)
        self.assertEqual(api.statuses[-1][2], "success")
        api.rows[0]["state"] = "DISMISSED"
        status.refresh_reviews(api)
        self.assertEqual(api.statuses[-1][2], "failure")
    def test_owner_solo_and_old_head_reviews(self):
        api = FakeAPI("marouanMesri")
        status.refresh_reviews(api)
        self.assertEqual(api.statuses[-1][2], "success")
        api.pr["user"]["login"] = "contributor"
        api.rows = [{"id": 1, "state": "APPROVED", "commit_id": "c" * 40, "user": {"login": "marouanMesri"}}]
        status.refresh_reviews(api)
        self.assertEqual(api.statuses[-1][2], "failure")
    def test_nondefault_target_cannot_pass(self):
        api = FakeAPI("marouanMesri")
        api.pr["base"]["ref"] = "old-branch"
        status.refresh_reviews(api)
        self.assertEqual(api.statuses[-1][2], "failure")
    def test_relay_must_be_exact_registered_workflow(self):
        api = FakeAPI()
        status.validate_relay_event(api, "workflow_run", {"workflow_run": {"id": 1}})
        with self.assertRaises(ValueError): status.validate_relay_event(api, "pull_request_review", {})
        with self.assertRaises(ValueError): status.validate_relay_event(api, "workflow_run", {"workflow_run": {"id": "1"}})


if __name__ == "__main__": unittest.main(verbosity=2)
