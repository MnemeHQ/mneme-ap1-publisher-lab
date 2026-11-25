"""AP1 B2.1 resolver: read-only observation and dry-run. No secrets, no writes.

Runs in the ``AP1 feedback resolve`` job of the publisher workflow, as
``python3 -I ap1/resolve.py``, only after the pin manifest was verified. It
re-fetches everything about the triggering gate run by GET (the only event
value used is the run id), applies the stage-A planner from the pinned Core
checkout, and emits five validated outputs, a fixed job summary and a bounded
evidence JSON of ids, enums, shas, HTTP statuses and match flags.

Fail-closed: any rejection or exception yields ``action=NO_WRITE`` and
``write_candidate=false``. ``write_candidate`` is true only when the planner,
run with the policy observation modelled (the policy variable is unreadable
with GITHUB_TOKEN, so policy is verified by the writer later), plans CREATE or
UPDATE and every other check held. Nothing untrusted is ever printed.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import os
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import common as C  # noqa: E402  (path set above; -I drops the script dir)

ZERO64 = "0" * 64
OBS = ("resolve", "before_write", "after_write")


# ── planner ──────────────────────────────────────────────────────────────────

def load_planner(core_dir: str):
    path = os.path.join(core_dir, "scripts", "ci", "publish_pr_feedback.py")
    spec = importlib.util.spec_from_file_location("ap1_core_publish_pr_feedback", path)
    C.require(spec is not None and spec.loader is not None, "PLANNER_MISSING")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    C.require(callable(getattr(module, "plan", None)), "PLANNER_MISSING")
    return module


def build_config(workflow_id: int, definition_blob: str, bot_id: int) -> dict:
    """Trusted planner config. Constants here, plus three host-sourced ids (see PR body)."""
    return {
        "repo_id": C.REPO_ID, "default_branch": C.DEFAULT_BRANCH,
        "producer": {"workflow_id": workflow_id, "path": C.GATE_PATH, "event": C.GATE_EVENT,
                     "gate_job_name": C.GATE_JOB, "evaluate_step": C.EVAL_STEP},
        "producer_definition": {"path": C.GATE_PATH, "blob_sha": definition_blob},
        "policy_version": C.APPROVED_POLICY_VERSION,
        "pins": {"adapter_sha256": C.ADAPTER_SHA256, "evaluator_commit": C.EVALUATOR_COMMIT,
                 "evaluator_wheel_sha256": C.EVALUATOR_WHEEL_SHA256, "mode": C.VIOLATION_MODE,
                 "posture": C.APPROVED_POSTURE},
        "publisher": {"actor_id": bot_id, "marker": C.MARKER, "names": list(C.PUBLISHER_NAMES)},
        "required_checks": [C.GATE_JOB],
        "limits": {"body_cap": 49152, "archive_compressed_max": C.ZIP_CAP,
                   "archive_uncompressed_max": C.ZIP_UNCOMPRESSED_CAP},
        "disclosure": "totals",
    }


def _job_view(job: dict) -> dict:
    steps = []
    for s in job.get("steps") or []:
        if not isinstance(s, dict):
            continue
        steps.append({"number": s.get("number"), "name": s.get("name"), "conclusion": s.get("conclusion"),
                      "started_at": C.utc_seconds(s.get("started_at"), ceil=False),
                      "completed_at": C.utc_seconds(s.get("completed_at"), ceil=True)})
    return {"name": job.get("name"), "id": job.get("id"), "run_id": job.get("run_id"),
            "head_sha": job.get("head_sha"), "status": job.get("status"),
            "run_attempt": job.get("run_attempt"), "conclusion": job.get("conclusion"), "steps": steps}


def _artifact_view(a: dict) -> dict:
    wr = a.get("workflow_run") if isinstance(a.get("workflow_run"), dict) else {}
    return {"id": a.get("id"), "name": a.get("name"), "size_in_bytes": a.get("size_in_bytes"),
            "digest": a.get("digest"), "expired": a.get("expired"),
            "created_at": C.utc_seconds(a.get("created_at"), ceil=False),
            "workflow_run": {"id": wr.get("id"), "repository_id": wr.get("repository_id"),
                             "head_sha": wr.get("head_sha"), "head_repository_id": wr.get("head_repository_id")}}


def _pull_view(p: dict) -> dict:
    return {"number": p.get("number"), "state": p.get("state"),
            "base": {"repo": {"id": C.dig(p, "base", "repo", "id")}, "ref": C.dig(p, "base", "ref"),
                     "sha": C.dig(p, "base", "sha")},
            "head": {"repo": {"id": C.dig(p, "head", "repo", "id")}, "sha": C.dig(p, "head", "sha")}}


def build_observed(ctx: dict, artifact: dict, zip_b64: str, definition_blob: str, other_runs: list,
                   other_complete: bool, comments: list, comments_complete: bool) -> dict:
    """Planner input from one real observation. Before/after-write observations are modelled copies."""
    run = ctx["run"]
    pull, ref = _pull_view(ctx["pull"]), {"object": {"sha": C.dig(ctx["ref"], "object", "sha")}}
    return {
        "source_run": {"id": run["id"], "repository": {"id": C.dig(run, "repository", "id")},
                       "workflow_id": run["workflow_id"], "path": run["path"], "event": run["event"],
                       "status": run["status"], "conclusion": run.get("conclusion"),
                       "run_number": run["run_number"], "head_sha": run["head_sha"],
                       "head_repository": {"id": C.dig(run, "head_repository", "id")}, "pull_requests": [],
                       "run_attempt_obs": {k: run["run_attempt"] for k in OBS}},
        "producer_definition": {"path": C.GATE_PATH, "blob_sha": definition_blob},
        "jobs": [_job_view(ctx["job"])],
        "artifacts": [_artifact_view(artifact)],
        "artifact_zip_b64": zip_b64,
        "base_ref_obs": {k: copy.deepcopy(ref) for k in OBS},
        "pull_obs": {k: copy.deepcopy(pull) for k in OBS},
        "other_runs": other_runs, "other_runs_complete": other_complete,
        "comments": comments, "comments_complete": comments_complete,
        "receipt": None,
    }


# ── observation helpers ──────────────────────────────────────────────────────

def observe_self(api, env: dict, git_head: str) -> dict:
    """H15a: what the host says about THIS run versus what the job sees."""
    rid = C.dec(env.get("GITHUB_RUN_ID"), "BAD_RUN_ID")
    st, run = api.get(f"/repos/{C.REPO}/actions/runs/{rid}")
    rec: dict = {"http_status": st}
    if st != 200 or not isinstance(run, dict):
        return rec
    for k in ("head_sha", "head_branch", "event", "path", "run_attempt", "workflow_id", "run_number"):
        rec[k] = run.get(k)
    gsha, gref = env.get("GITHUB_SHA"), env.get("GITHUB_REF")
    ref_name = gref[len("refs/heads/"):] if isinstance(gref, str) and gref.startswith("refs/heads/") else None

    def flag(ok: bool) -> str:
        return "match" if ok else "mismatch"

    rec["env_github_sha"], rec["env_github_ref"] = gsha, gref
    rec["git_head"] = git_head
    rec["run_head_sha_vs_github_sha"] = flag(run.get("head_sha") == gsha)
    rec["run_head_sha_vs_git_head"] = flag(run.get("head_sha") == git_head)
    rec["github_sha_vs_git_head"] = flag(gsha == git_head)
    rec["run_head_branch_vs_github_ref"] = flag(ref_name is not None and run.get("head_branch") == ref_name)
    rec["repository_id"] = C.dig(run, "repository", "id")
    st, wf = api.get(f"/repos/{C.REPO}/actions/workflows/{C.PUBLISHER_FILE}")
    rec["workflow_id_vs_file_lookup"] = flag(st == 200 and C.dig(wf, "id") == run.get("workflow_id"))
    return rec


def add_gate_comparison(rec: dict, gate_head_sha: str, gate_head_branch: object) -> None:
    """What the host reports for a workflow_run: the triggering run's head, or main's?"""
    if "head_sha" in rec:
        rec["run_head_sha_vs_gate_head_sha"] = "match" if rec["head_sha"] == gate_head_sha else "mismatch"
        rec["run_head_branch_vs_gate_head_branch"] = ("match" if rec.get("head_branch") == gate_head_branch
                                                      else "mismatch")


def git_head(repo_root: str) -> str:
    out = subprocess.run(["git", "-C", repo_root, "rev-parse", "HEAD"], capture_output=True, timeout=20,
                         check=False, text=True)
    v = out.stdout.strip()
    return v if out.returncode == 0 and C.SHA40_RE.fullmatch(v) else "UNKNOWN"


def fetch_artifact(api, gate_id: str, pr: int) -> tuple[dict, bytes]:
    items, complete, _ = C.paged(api, f"/repos/{C.REPO}/actions/runs/{gate_id}/artifacts", {}, key="artifacts")
    C.require(complete, "ARTIFACTS_INCOMPLETE")
    named = [a for a in items if isinstance(a, dict) and isinstance(a.get("name"), str)
             and a["name"].startswith("mneme-gate-pr")]
    C.require(len(named) == 1, "ARTIFACT_COUNT")
    art = named[0]
    m = C.ARTIFACT_NAME_RE.fullmatch(art["name"])
    C.require(m is not None and m.group(2) == gate_id and m.group(1) == str(pr), "ARTIFACT_NAME")
    C.require(art.get("expired") is False and C.is_int(art.get("id")) and C.is_int(art.get("size_in_bytes"))
              and 0 < art["size_in_bytes"] <= C.ZIP_CAP and isinstance(art.get("digest"), str), "ARTIFACT_META")
    data = api.download(f"/repos/{C.REPO}/actions/artifacts/{art['id']}/zip")
    C.require(len(data) == art["size_in_bytes"], "ARTIFACT_SIZE")
    C.require(art["digest"] == "sha256:" + hashlib.sha256(data).hexdigest(), "ARTIFACT_DIGEST")
    C.inspect_zip(data)
    return art, data


def comment_views(raw: list) -> tuple[list, dict]:
    """Planner-shaped comments plus counts. Bodies go only to the planner, never to evidence."""
    views, owned, foreign = [], 0, 0
    for c in raw:
        if not isinstance(c, dict):
            views.append(c)
            continue
        user = c.get("user") if isinstance(c.get("user"), dict) else {}
        body = c.get("body") if isinstance(c.get("body"), str) else ""
        first = body.split("\n", 1)[0]
        if user.get("login") == C.BOT_LOGIN and first == C.MARKER_LINE:
            owned += 1
        elif first.strip() == C.MARKER_LINE:
            foreign += 1
        views.append({"id": c.get("id"), "body": c.get("body"), "updated_at": c.get("updated_at"),
                      "user": {"id": user.get("id"), "type": user.get("type")}})
    return views, {"count": len(raw), "owned_marker": owned, "foreign_marker": foreign}


# ── the resolve pipeline ─────────────────────────────────────────────────────

def run(env: dict, api, repo_root: str, core_dir: str, head: str) -> tuple[dict, dict]:
    """Returns (outputs, evidence). Never raises; every failure is NO_WRITE / false."""
    out = {"action": "NO_WRITE", "write_candidate": "false", "pr": "0", "gate_run": "0",
           "manifest_sha256": ZERO64}
    ev: dict = {"schema": "ap1.resolve.v1", "reject": None, "write_candidate_basis": "none"}
    try:
        out["manifest_sha256"] = C.sha256_file(os.path.join(repo_root, C.PINS_FILE))
        ev["manifest_sha256"] = out["manifest_sha256"]
        ev["repo_id"] = C.REPO_ID
        ev["core_commit"] = C.CORE_COMMIT
        gate_id = C.dec(env.get("GATE_RUN_ID"), "BAD_GATE_RUN")
        out["gate_run"] = gate_id
        ev["publisher"] = {"run_id": env.get("GITHUB_RUN_ID"), "run_attempt": env.get("GITHUB_RUN_ATTEMPT"),
                           "event": env.get("GITHUB_EVENT_NAME"), "ref": env.get("GITHUB_REF")}
        # H15a first, so it is recorded even when the gate-run check rejects below.
        ev["h15a"] = observe_self(api, env, head)
        try:  # own-run identity gates write_candidate; observations are kept either way
            C.own_identity(api, env, head)
            ev["own_identity"] = "ok"
        except C.Reject as err:
            ev["own_identity"] = err.code
        ctx = C.gate_context(api, gate_id)
        out["pr"] = str(ctx["pr"])
        ev["gate"] = {"run_id": ctx["run"]["id"], "run_number": ctx["run"]["run_number"],
                      "workflow_id": ctx["run"]["workflow_id"], "conclusion": ctx["run"].get("conclusion"),
                      "job_conclusion": ctx["job"].get("conclusion"),
                      "evaluate_step_conclusion": ctx["eval_step"].get("conclusion"),
                      "head_sha": ctx["head_sha"], "head_branch": ctx["run"].get("head_branch"),
                      "base_sha": ctx["base_sha"], "pr": ctx["pr"],
                      "pr_base_ref": C.dig(ctx["pull"], "base", "ref"),
                      "identity": "partially_verified", "base_fresh_at_resolve": True}
        add_gate_comparison(ev["h15a"], ctx["head_sha"], ctx["run"].get("head_branch"))

        artifact, zip_bytes = fetch_artifact(api, gate_id, ctx["pr"])
        ev["artifact"] = {"count": 1, "size": artifact["size_in_bytes"], "expired": False, "zip": "inspected_ok"}

        # Policy-metadata feasibility: status only, never a fallback.
        st, _ = api.get(f"/repos/{C.REPO}/actions/variables/{C.VARIABLE_NAME}")
        ev["policy"] = {"variable_http_status": st, "live_check": "pending_writer",
                        "expected_posture": C.APPROVED_POSTURE,
                        "expected_posture_label": "closed_owner_approved_constant"}

        raw_comments, complete, cst = C.paged(api, f"/repos/{C.REPO}/issues/{ctx['pr']}/comments", {})
        views, counts = comment_views(raw_comments)
        ev["comments"] = dict(counts, http_status=cst, complete=complete)

        st, wf = api.get(f"/repos/{C.REPO}/actions/workflows/{C.GATE_FILE}")
        C.require(st == 200 and C.dig(wf, "id") == ctx["run"]["workflow_id"], "WORKFLOW_ID")
        runs, runs_complete, _ = C.paged(api, f"/repos/{C.REPO}/actions/workflows/{wf['id']}/runs", {},
                                         key="workflow_runs")
        others = [{"id": r.get("id"), "run_number": r.get("run_number"), "run_attempt": r.get("run_attempt")}
                  for r in runs if isinstance(r, dict)]
        ev["other_runs"] = {"count": len(others), "complete": runs_complete}

        st, contents = api.get(f"/repos/{C.REPO}/contents/{C.GATE_PATH}", {"ref": ctx["base_sha"]})
        remote_blob = C.dig(contents, "sha")
        with open(os.path.join(repo_root, C.GATE_PATH), "rb") as fh:
            local_blob = C.blob_sha1(fh.read())
        # The definition the gate run actually used is NOT observable: both blobs are main's copy.
        ev["definition"] = {"binding": "main_copy_assumed_not_observed", "http_status": st,
                            "main_tip_blob_equals_checkout": remote_blob == local_blob}

        st, bot = api.get("/users/mneme-ap1-lab-publisher%5Bbot%5D")
        bot_ok = st == 200 and C.dig(bot, "login") == C.BOT_LOGIN and C.dig(bot, "type") == "Bot" \
            and C.is_int(C.dig(bot, "id"))
        ev["publisher_identity"] = {"http_status": st, "resolved": bool(bot_ok)}
        C.require(bot_ok, "BOT_UNRESOLVED")

        zip_b64 = base64.b64encode(zip_bytes).decode("ascii")
        planner = load_planner(core_dir)
        config = build_config(wf["id"], local_blob, bot["id"])
        observed = build_observed(ctx, artifact, zip_b64, local_blob, others, runs_complete, views, complete)
        actual = planner.plan(copy.deepcopy(config), copy.deepcopy(observed))
        modelled = copy.deepcopy(observed)
        modelled["policy"] = {k: {"posture": C.APPROVED_POSTURE, "version": C.APPROVED_POLICY_VERSION} for k in OBS}
        dry = planner.plan(copy.deepcopy(config), modelled)
        ev["plan"] = {"actual_action": actual.get("action"), "actual_reason": actual.get("reason"),
                      "dry_run_action": dry.get("action"), "dry_run_reason": dry.get("reason"),
                      "policy_observations": "pending_writer", "before_write_after_write": "pending_writer"}
        if dry.get("action") in C.ACTIONS:
            out["action"] = dry["action"]
        gate_ok = (ev["own_identity"] == "ok" and ev["definition"]["main_tip_blob_equals_checkout"]
                   and ev["h15a"].get("http_status") == 200)
        if dry.get("action") in ("CREATE", "UPDATE") and gate_ok:
            out["write_candidate"] = "true"
            ev["write_candidate_basis"] = "conditional_non_policy_checks_resolve_time_only"
    except C.Reject as err:
        ev["reject"] = err.code
    except Exception:  # noqa: BLE001 - any fault is NO_WRITE, never a write candidate
        ev["reject"] = "INTERNAL"
    if ev["reject"] is not None:
        out["action"], out["write_candidate"] = "NO_WRITE", "false"
        ev["write_candidate_basis"] = "none"
    ev["outputs"] = dict(out)
    return out, ev


def render_summary(env: dict, out: dict) -> str:
    """Fixed template; each field is validated, so no untrusted text can appear."""
    ref = env.get("GITHUB_REF", "")
    fields = {
        "run": env.get("GITHUB_RUN_ID", ""), "attempt": env.get("GITHUB_RUN_ATTEMPT", ""),
        "event": env.get("GITHUB_EVENT_NAME", ""), "ref": ref,
    }
    ok = (C.DEC_RE.fullmatch(fields["run"]) and C.DEC_RE.fullmatch(fields["attempt"])
          and fields["event"] == "workflow_run" and C.TOKEN_RE.fullmatch(ref) and "::" not in ref)
    if not ok:
        fields = {"run": "invalid", "attempt": "invalid", "event": "invalid", "ref": "invalid"}
    return (
        "## AP1 feedback resolve (B2.1, read-only)\n\n"
        f"- Publisher workflow: `{C.PUBLISHER_PATH}`\n"
        f"- Event: `{fields['event']}`\n"
        f"- Ref: `{fields['ref']}`\n"
        f"- Publisher run: `{fields['run']}` (attempt `{fields['attempt']}`)\n"
        f"- Triggering gate run: `{out['gate_run']}`\n"
        f"- Pin-manifest hash: `{out['manifest_sha256']}`\n"
        f"- Repository id: `{C.REPO_ID}`\n"
        f"- Pull request: `{out['pr']}`\n"
        f"- Proposed action: `{out['action']}`\n"
        f"- Write candidate: `{'true' if out['write_candidate'] == 'true' else 'false'}`\n"
        f"- Expected posture (owner-approved constant, not verified): `{C.APPROVED_POSTURE}`\n"
        "\nPolicy check: pending (verified by writer before any write)\n"
    )


def main() -> int:
    env = dict(os.environ)
    repo_root = os.getcwd()
    try:
        api = C.Api(env.get("GITHUB_TOKEN", ""))
    except C.Reject:
        api = None
    if api is None:
        out = {"action": "NO_WRITE", "write_candidate": "false", "pr": "0", "gate_run": "0",
               "manifest_sha256": ZERO64}
        ev = {"schema": "ap1.resolve.v1", "reject": "NO_TOKEN", "write_candidate_basis": "none"}
    else:
        out, ev = run(env, api, repo_root, os.path.join(repo_root, "core"), git_head(repo_root))
    C.log("resolve action=" + out["action"] + " write_candidate=" + out["write_candidate"])
    C.log("resolve reject=" + C.safe_token(str(ev.get("reject"))))
    if env.get("GITHUB_OUTPUT"):
        C.write_outputs(env["GITHUB_OUTPUT"], out)
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8", newline="\n") as fh:
            fh.write(render_summary(env, out))
    if env.get("EVIDENCE_PATH"):
        C.write_evidence(env["EVIDENCE_PATH"], ev)
    return 0


if __name__ == "__main__":
    sys.exit(main())
