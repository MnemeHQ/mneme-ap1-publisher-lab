"""resolve.py and write_canary.py end to end against a synthetic, offline world (needs the pinned Core planner)."""
from __future__ import annotations

import json
import os
import re

import pytest

import common as C
import resolve as R
import write_canary as W
from conftest import World, make_zip, report

ZERO = "0" * 64


def _go(world, core_dir, repo_root, api=None):
    return R.run(world.env, api or world.api(), repo_root, core_dir, "a" * 40)


def test_happy_path_is_candidate_but_real_plan_abstains_on_policy(world, core_dir, repo_root):
    out, ev = _go(world, core_dir, repo_root)
    assert ev["reject"] is None
    assert out["action"] == "CREATE" and out["write_candidate"] == "true"
    assert out["pr"] == str(world.PR) and out["gate_run"] == str(world.GATE)
    assert out["manifest_sha256"] != ZERO
    assert ev["plan"]["actual_action"] == "NO_WRITE" and ev["plan"]["actual_reason"] == "POLICY_UNPROVEN"
    assert ev["plan"]["dry_run_action"] == "CREATE"
    assert ev["policy"] == {"variable_http_status": 403, "live_check": "pending_writer",
                            "expected_posture": "closed", "expected_posture_label": "closed_owner_approved_constant"}
    assert ev["write_candidate_basis"] == "conditional_non_policy_checks_resolve_time_only"
    assert ev["plan"]["policy_observations"] == "pending_writer"
    assert ev["plan"]["before_write_after_write"] == "pending_writer"
    assert "modelled" not in json.dumps(ev) and "verified" not in json.dumps(ev["definition"])
    assert ev["definition"]["binding"] == "main_copy_assumed_not_observed"
    assert ev["gate"]["identity"] == "partially_verified" and ev["own_identity"] == "ok"
    C.format_outputs(out)  # validates


def test_h15a_flags_recorded(world, core_dir, repo_root):
    _, ev = _go(world, core_dir, repo_root)
    h = ev["h15a"]
    assert h["run_head_sha_vs_github_sha"] == "mismatch"  # GITHUB_SHA is 'a'*40 here, run head is the PR head
    assert h["github_sha_vs_git_head"] == "match"
    assert h["run_head_branch_vs_github_ref"] == "mismatch"
    assert h["run_head_sha_vs_gate_head_sha"] == "match" and h["run_head_branch_vs_gate_head_branch"] == "match"
    assert h["workflow_id_vs_file_lookup"] == "match" and h["repository_id"] == C.REPO_ID
    assert h["event"] == "workflow_run" and h["run_attempt"] == 1
    assert ev["gate"]["head_branch"] == "feat/x" and ev["gate"]["pr_base_ref"] == "main"


def test_evidence_has_no_bodies_and_is_bounded(world, core_dir, repo_root):
    world.comments.append({"id": 1, "body": C.MARKER_LINE + "\nSECRET-BODY-TEXT", "updated_at": "2026-01-01T00:00:00Z",
                           "user": {"id": 5, "type": "User", "login": "mallory"}})
    out, ev = _go(world, core_dir, repo_root)
    data = C.evidence_bytes(ev).decode("ascii")
    assert "SECRET-BODY-TEXT" not in data and "mallory" not in data and "gate-report" not in data
    assert len(data) <= C.EVIDENCE_CAP
    assert ev["comments"]["foreign_marker"] == 1 and ev["comments"]["owned_marker"] == 0
    assert out["write_candidate"] == "false" and out["action"] == "CONFLICT"  # foreign marker blocks


def test_owned_comment_without_receipt_is_not_a_candidate(world, core_dir, repo_root):
    world.comments.append({"id": 1, "body": C.MARKER_LINE + "\nold", "updated_at": "2026-01-01T00:00:00Z",
                           "user": {"id": world.BOT, "type": "Bot", "login": C.BOT_LOGIN}})
    out, ev = _go(world, core_dir, repo_root)
    assert ev["comments"]["owned_marker"] == 1
    assert out["write_candidate"] == "false"  # no receipt store in B2.1: CONFLICT


FAILURES = {
    "wrong_path": lambda w: w.run.__setitem__("path", ".github/workflows/x.yml"),
    "wrong_event": lambda w: w.run.__setitem__("event", "pull_request"),
    "attempt_2": lambda w: w.run.__setitem__("run_attempt", 2),
    "wrong_repo": lambda w: w.run.__setitem__("repository", {"id": 4}),
    "no_job": lambda w: w.job.__setitem__("name", "other"),
    "artifact_expired": lambda w: w.art.__setitem__("expired", True),
    "artifact_oversize": lambda w: w.art.__setitem__("size_in_bytes", C.ZIP_CAP + 1),
    "artifact_bad_name": lambda w: w.art.__setitem__("name", "mneme-gate-pr7-1"),
    "artifact_wrong_pr": lambda w: w.art.__setitem__("name", f"mneme-gate-pr8-{w.GATE}"),
    "artifact_digest": lambda w: w.art.__setitem__("digest", "sha256:" + "0" * 64),
    "pr_closed": lambda w: w.pull.__setitem__("state", "closed"),
    "fork_head": lambda w: w.pull["head"].__setitem__("repo", {"id": 9}),
    "bad_run_id": lambda w: w.env.__setitem__("GATE_RUN_ID", "1; rm -rf /"),
    "missing_run_id": lambda w: w.env.pop("GATE_RUN_ID"),
    "stale_main": lambda w: w.pull["base"].__setitem__("sha", "e" * 40),
}


@pytest.mark.parametrize("name", sorted(FAILURES))
def test_failures_never_produce_a_candidate(name, world, core_dir, repo_root):
    FAILURES[name](world)
    out, ev = _go(world, core_dir, repo_root)
    assert out["write_candidate"] == "false" and out["action"] == "NO_WRITE"
    assert ev["reject"] is not None and ev["write_candidate_basis"] == "none"
    C.format_outputs(out)


def test_two_artifacts_and_zero_artifacts(world, core_dir, repo_root):
    api = world.api()
    p = f"/repos/{C.REPO}/actions/runs/{world.GATE}/artifacts"
    api.routes[p] = (200, {"artifacts": [world.art, dict(world.art, id=2)]})
    out, ev = _go(world, core_dir, repo_root, api)
    assert out["write_candidate"] == "false" and ev["reject"] == "ARTIFACT_COUNT"
    api.routes[p] = (200, {"artifacts": []})
    out, ev = _go(world, core_dir, repo_root, api)
    assert out["write_candidate"] == "false" and ev["reject"] == "ARTIFACT_COUNT"
    api.routes[p] = (403, None)
    out, ev = _go(world, core_dir, repo_root, api)
    assert out["write_candidate"] == "false" and ev["reject"] == "ARTIFACTS_INCOMPLETE"


@pytest.mark.parametrize("entries,code", [
    ([("gate-report.json", b"{}"), ("../x", b"1")], "ZIP_SLIP"),
    ([("gate-report.json", b"{}"), ("gate-report.json", b"{}")], "ZIP_DUPLICATE"),
    ([("gate-report.json", b"0" * (C.ZIP_UNCOMPRESSED_CAP + 1))], "ZIP_TOO_BIG"),
])
def test_hostile_archives_are_rejected(entries, code, world, core_dir, repo_root):
    z = make_zip(entries)
    import hashlib
    world.zip = z
    world.art.update(size_in_bytes=len(z), digest="sha256:" + hashlib.sha256(z).hexdigest())
    out, ev = _go(world, core_dir, repo_root)
    assert out["write_candidate"] == "false" and ev["reject"] == code


def test_pr_ambiguity_blocks(world, core_dir, repo_root):
    api = world.api()
    api.routes[f"/repos/{C.REPO}/commits/{world.head}/pulls"] = (200, [world.pull, dict(world.pull, number=99)])
    out, ev = _go(world, core_dir, repo_root, api)
    assert out["write_candidate"] == "false" and ev["reject"] == "PR_AMBIGUOUS"


def test_unresolved_bot_blocks(world, core_dir, repo_root):
    api = world.api()
    api.routes["/users/mneme-ap1-lab-publisher%5Bbot%5D"] = (404, None)
    out, ev = _go(world, core_dir, repo_root, api)
    assert out["write_candidate"] == "false" and ev["reject"] == "BOT_UNRESOLVED"


def test_definition_blob_mismatch_blocks(world, core_dir, repo_root):
    api = world.api()
    api.routes[f"/repos/{C.REPO}/contents/{C.GATE_PATH}"] = (200, {"sha": "0" * 40})
    out, _ = _go(world, core_dir, repo_root, api)
    assert out["write_candidate"] == "false"


def test_incomplete_comments_and_runs_block(world, core_dir, repo_root):
    api = world.api()
    api.routes[f"/repos/{C.REPO}/issues/{world.PR}/comments"] = (403, None)
    out, ev = _go(world, core_dir, repo_root, api)
    assert out["write_candidate"] == "false" and ev["plan"]["dry_run_reason"] == "COMMENTS_INCOMPLETE"
    api = world.api()
    api.routes[f"/repos/{C.REPO}/actions/workflows/{world.WF}/runs"] = (403, None)
    out, ev = _go(world, core_dir, repo_root, api)
    assert out["write_candidate"] == "false" and ev["plan"]["dry_run_reason"] == "ORDER_UNPROVEN"


def test_later_gate_run_makes_this_one_stale(world, core_dir, repo_root):
    world.other_runs.append({"id": 1, "run_number": 13, "run_attempt": 1})
    out, ev = _go(world, core_dir, repo_root)
    assert out["write_candidate"] == "false" and ev["plan"]["dry_run_reason"] == "STALE_RUN"


def test_open_posture_report_is_unavailable_not_candidate(core_dir, repo_root):
    w = World(report("L5"), repo_root)  # recorded posture open; the approved constant is closed
    out, ev = _go(w, core_dir, repo_root)
    assert out["write_candidate"] == "false" and out["action"] == "UNAVAILABLE"
    assert ev["plan"]["dry_run_reason"] == "REPORT_UNAVAILABLE"


def test_closed_posture_reports_give_a_candidate(core_dir, repo_root):
    clean = World(report("L1"), repo_root)
    out, _ = _go(clean, core_dir, repo_root)
    assert out["action"] == "CREATE" and out["write_candidate"] == "true"
    viol = report("L5")  # strict violation, recorded under open; re-recorded as closed (still failure)
    viol["posture"] = dict(viol["posture"], effective="closed")
    w = World(viol, repo_root)
    out, ev = _go(w, core_dir, repo_root)
    assert ev["plan"]["dry_run_action"] == "CREATE" and out["write_candidate"] == "true", ev["plan"]


OWN_FAILURES = {
    "env_attempt_2": lambda w: w.env.__setitem__("GITHUB_RUN_ATTEMPT", "2"),
    "run_attempt_2": lambda w: w.own.__setitem__("run_attempt", 2),
    "wrong_path": lambda w: w.own.__setitem__("path", ".github/workflows/other.yml"),
    "wrong_event_env": lambda w: w.env.__setitem__("GITHUB_EVENT_NAME", "push"),
    "wrong_event_run": lambda w: w.own.__setitem__("event", "push"),
    "wrong_repo": lambda w: w.own.__setitem__("repository", {"id": 3}),
    "wrong_ref": lambda w: w.env.__setitem__("GITHUB_REF", "refs/heads/evil"),
    "sha_not_head": lambda w: w.env.__setitem__("GITHUB_SHA", "b" * 40),
    "own_run_unreadable": lambda w: w.env.__setitem__("GITHUB_RUN_ID", "424242"),
}


@pytest.mark.parametrize("name", sorted(OWN_FAILURES))
def test_wrong_own_run_identity_is_never_a_candidate(name, world, core_dir, repo_root):
    OWN_FAILURES[name](world)
    out, ev = _go(world, core_dir, repo_root)
    assert out["write_candidate"] == "false"
    assert ev["own_identity"].startswith("OWN_") and ev["reject"] is None  # observations are still recorded
    assert ev["plan"]["dry_run_action"] == "CREATE"  # the gate side was fine; only own identity blocks


def test_exception_in_planner_is_no_write(world, core_dir, repo_root, monkeypatch):
    monkeypatch.setattr(R, "load_planner", lambda d: (_ for _ in ()).throw(RuntimeError("boom ::error::x")))
    out, ev = _go(world, core_dir, repo_root)
    assert out["write_candidate"] == "false" and out["action"] == "NO_WRITE" and ev["reject"] == "INTERNAL"


def test_planner_returning_garbage_is_no_write(world, core_dir, repo_root, monkeypatch):
    class Fake:
        @staticmethod
        def plan(c, o):
            return {"action": "::add-mask::x"}
    monkeypatch.setattr(R, "load_planner", lambda d: Fake)
    out, _ = _go(world, core_dir, repo_root)
    assert out["write_candidate"] == "false" and out["action"] == "NO_WRITE"


# ── F5: hostile text never reaches outputs, summary, evidence or stdout ──────

HOSTILE = ["::add-mask::tok123", "::stop-commands::abc", "::error::boom", "x\r\ny", "ghadelimiter_zzz",
           "a\nwrite_candidate=true"]


def test_hostile_comment_and_report_text_never_leaks(world, core_dir, repo_root, capsys, tmp_path):
    for i, h in enumerate(HOSTILE):
        world.comments.append({"id": i + 1, "body": h + "\n" + h, "updated_at": h,
                               "user": {"id": i, "type": h, "login": h}})
    out, ev = _go(world, core_dir, repo_root)
    env = dict(world.env, GITHUB_REF="::error::x\nfoo")  # hostile env value
    summary = R.render_summary(env, out)
    blob = json.dumps(out) + summary + C.evidence_bytes(ev).decode() + capsys.readouterr().out
    for h in HOSTILE:
        assert h not in blob
    assert "::" not in summary and "\r" not in summary
    # comments that merely contain hostile text (no marker first line) are ignored by the planner
    assert ev["comments"]["foreign_marker"] == 0 and ev["comments"]["count"] == len(HOSTILE)
    # every line of the summary is from the fixed template
    allowed = re.compile(r"^(## AP1 feedback resolve \(B2\.1, read-only\)|- [A-Za-z -]+( \([A-Za-z ,-]+\))?: `[A-Za-z0-9._/:@-]+`( \(attempt `[A-Za-z0-9]+`\))?|"
                         r"Policy check: pending \(verified by writer before any write\)|)$")
    assert all(allowed.match(l) for l in summary.split("\n")), summary


def test_summary_fixed_fields(world):
    out = {"action": "CREATE", "write_candidate": "true", "pr": "7", "gate_run": "55", "manifest_sha256": "ab" * 32}
    s = R.render_summary(dict(world.env), out)
    for needle in (C.PUBLISHER_PATH, "`workflow_run`", "refs/heads/main", f"`{world.OWN}`", "`55`", "ab" * 32,
                   str(C.REPO_ID), "Proposed action: `CREATE`", "Expected posture (owner-approved constant, not verified): `closed`",
                   "Policy check: pending (verified by writer before any write)"):
        assert needle in s
    bad = R.render_summary(dict(world.env, GITHUB_EVENT_NAME="push"), out)
    assert "`invalid`" in bad


def test_main_writes_outputs_summary_evidence(world, core_dir, repo_root, tmp_path, monkeypatch, capsys):
    out_file, sum_file, ev_file = tmp_path / "o", tmp_path / "s", tmp_path / "e" / "obs.json"
    api = world.api()
    monkeypatch.setattr(C, "Api", lambda tok: api)
    monkeypatch.setattr(R, "git_head", lambda root: "a" * 40)
    for k, v in dict(world.env, GITHUB_TOKEN="t", GITHUB_OUTPUT=str(out_file), GITHUB_STEP_SUMMARY=str(sum_file),
                     EVIDENCE_PATH=str(ev_file)).items():
        monkeypatch.setenv(k, v)
    monkeypatch.chdir(repo_root)
    os.symlink  # noqa: B018 - presence only
    # core dir is expected at <cwd>/core
    import shutil
    shutil.copytree(core_dir, os.path.join(repo_root, "core"))
    assert R.main() == 0
    lines = out_file.read_text().splitlines()
    assert [l.split("=")[0] for l in lines] == ["action", "write_candidate", "pr", "gate_run", "manifest_sha256"]
    assert "Policy check: pending" in sum_file.read_text()
    assert json.loads(ev_file.read_text())["schema"] == "ap1.resolve.v1"
    assert "token" not in capsys.readouterr().out.lower()


def test_main_without_token_is_no_write(tmp_path, monkeypatch):
    out_file = tmp_path / "o"
    for k in ("GITHUB_TOKEN",):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "s"))
    monkeypatch.setenv("EVIDENCE_PATH", str(tmp_path / "ev.json"))
    assert R.main() == 0
    text = out_file.read_text()
    assert "action=NO_WRITE" in text and "write_candidate=false" in text


# ── write canary ─────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _fake_git_head(monkeypatch):
    monkeypatch.setattr(R, "git_head", lambda root: "a" * 40)

def _canary_env(world):
    return dict(world.env, RESOLVED_PR=str(world.PR), RESOLVED_GATE_RUN=str(world.GATE),
                RESOLVED_MANIFEST_SHA256=C.sha256_file(os.path.join(world.root, C.PINS_FILE)))


def test_canary_records_context_and_writes_nothing(world, repo_root):
    api = world.api()
    R_ = f"/repos/{C.REPO}/actions/runs/{world.OWN}"
    api.routes[R_ + "/approvals"] = (200, [{"state": "approved", "user": {"id": 1, "login": "TheoV823"},
                                            "environments": [{"name": C.ENVIRONMENT}], "comment": "::error::x"}])
    api.routes[R_ + "/pending_deployments"] = (403, None)
    ev = W.run(_canary_env(world), api, repo_root)
    assert ev["reject"] is None and ev["gate"]["identity"] == "partially_verified"
    assert ev["manifest"]["equal"] is True and ev["own_identity"] == "ok"
    assert ev["publisher"]["github_sha_vs_git_head"] == "match"
    calls = {(c["call"], c["status"]) for c in ev["http_statuses"]}
    assert (f"/repos/{C.REPO}/commits/N/pulls", 200) in calls and (f"/repos/{C.REPO}/pulls/N", 200) in calls
    assert ev["approval_context"]["approvals"][0]["login"] == "TheoV823"
    assert ev["approval_context"]["pending_deployments_http_status"] == 403
    assert "::error" not in C.evidence_bytes(ev).decode()
    assert ev["secrets_referenced"] is False and ev["github_writes"] is False
    assert all(c.startswith(("/repos/", "/users/")) for c in api.calls)


def test_canary_approvals_denied_is_recorded(world, repo_root):
    ev = W.run(_canary_env(world), world.api(), repo_root)  # approvals route absent -> 404
    assert ev["approval_context"]["approvals_http_status"] == 404 and ev["reject"] is None


@pytest.mark.parametrize("mut", [
    lambda w, e: w.run.__setitem__("path", "x"),
    lambda w, e: w.run.__setitem__("run_attempt", 2),
    lambda w, e: e.__setitem__("RESOLVED_PR", "8"),
    lambda w, e: e.__setitem__("RESOLVED_GATE_RUN", "1"),
    lambda w, e: e.__setitem__("RESOLVED_MANIFEST_SHA256", "0" * 64),
    lambda w, e: e.__setitem__("GITHUB_RUN_ATTEMPT", "2"),
    lambda w, e: w.own.__setitem__("run_attempt", 2),
    lambda w, e: w.own.__setitem__("path", "x"),
    lambda w, e: e.__setitem__("GITHUB_REF", "refs/heads/evil"),
    lambda w, e: e.__setitem__("GITHUB_SHA", "b" * 40),
    lambda w, e: e.__setitem__("RESOLVED_PR", "7\nx"),
])
def test_canary_rechecks_identity(world, repo_root, mut):
    env = _canary_env(world)
    mut(world, env)
    ev = W.run(env, world.api(), repo_root)
    assert ev["reject"] is not None and "gate" not in ev
