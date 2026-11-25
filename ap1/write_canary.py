"""AP1 B2.1 write-job canary: NO KEY, writes nothing to GitHub.

Runs in the ``AP1 feedback write`` job (environment ``ap1-publisher-lab``,
``actions: read`` and ``contents: read`` only). It re-fetches this run and the
producer gate run, re-applies the same identity rules as the resolver, records
the deployment-approval context the job can see (who approved, or the HTTP
status when that is denied) and uploads one bounded evidence JSON through the
workflow's own upload step. It references no secret and calls no write API.
"""
from __future__ import annotations

import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import common as C  # noqa: E402
import resolve as R  # noqa: E402


def observe_approvals(api, run_id: str) -> dict:
    rec: dict = {}
    st, obj = api.get(f"/repos/{C.REPO}/actions/runs/{run_id}/approvals")
    rec["approvals_http_status"] = st
    if st == 200 and isinstance(obj, list):
        items = []
        for a in obj[:16]:
            if not isinstance(a, dict):
                continue
            user = a.get("user") if isinstance(a.get("user"), dict) else {}
            envs = [e.get("name") for e in (a.get("environments") or []) if isinstance(e, dict)][:4]
            items.append({"user_id": user.get("id"), "login": user.get("login"), "state": a.get("state"),
                          "environments": envs})
        rec["approvals_count"] = len(obj)
        rec["approvals"] = items
    st, _ = api.get(f"/repos/{C.REPO}/actions/runs/{run_id}/pending_deployments")
    rec["pending_deployments_http_status"] = st
    return rec


def run(env: dict, api, repo_root: str) -> dict:
    """Returns the evidence dict. Never raises."""
    ev: dict = {"schema": "ap1.write-canary.v1", "reject": None, "environment": C.ENVIRONMENT,
                "secrets_referenced": False, "github_writes": False}
    try:
        gate_id = C.dec(env.get("GATE_RUN_ID"), "BAD_GATE_RUN")
        resolved_pr = C.dec(env.get("RESOLVED_PR"), "BAD_RESOLVED_PR")
        resolved_gate = C.dec(env.get("RESOLVED_GATE_RUN"), "BAD_RESOLVED_GATE_RUN")
        C.require(resolved_gate == gate_id, "GATE_RUN_CHANGED")
        run_id = C.dec(env.get("GITHUB_RUN_ID"), "BAD_RUN_ID")
        ev["publisher"] = {"run_id": run_id, "run_attempt": env.get("GITHUB_RUN_ATTEMPT"),
                           "event": env.get("GITHUB_EVENT_NAME"), "ref": env.get("GITHUB_REF"),
                           "sha": env.get("GITHUB_SHA")}
        ev["h15a"] = R.observe_self(api, env, R.git_head(repo_root))
        ev["approval_context"] = observe_approvals(api, run_id)
        ctx = C.gate_context(api, gate_id)
        C.require(str(ctx["pr"]) == resolved_pr, "PR_CHANGED")
        ev["gate"] = {"run_id": ctx["run"]["id"], "head_sha": ctx["head_sha"], "base_sha": ctx["base_sha"],
                      "pr": ctx["pr"], "identity": "verified", "base_fresh": True}
    except C.Reject as err:
        ev["reject"] = err.code
    except Exception:  # noqa: BLE001
        ev["reject"] = "INTERNAL"
    return ev


def main() -> int:
    env = dict(os.environ)
    try:
        api = C.Api(env.get("GITHUB_TOKEN", ""))
        ev = run(env, api, os.getcwd())
    except C.Reject as err:
        ev = {"schema": "ap1.write-canary.v1", "reject": err.code, "secrets_referenced": False,
              "github_writes": False}
    C.log("canary reject=" + C.safe_token(str(ev.get("reject"))))
    if env.get("EVIDENCE_PATH"):
        C.write_evidence(env["EVIDENCE_PATH"], ev)
    return 0


if __name__ == "__main__":
    sys.exit(main())
