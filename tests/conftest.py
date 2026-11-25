"""Offline fixtures for the AP1 B2.1 bootstrap tests (stdlib + pytest, no network).

The planner and the historical gate reports come from MnemeHQ/mneme at the
pinned commit. They are read from a local Core checkout (AP1_CORE_REPO, default
C:/dev/mneme, or ../mneme) with ``git show``; nothing is copied into this repo.
Tests that need them skip when no checkout holds the pinned commit.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import warnings
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ap1"))
sys.dont_write_bytecode = True

import common as C  # noqa: E402
import resolve as R  # noqa: E402

REPORT_PATH = "docs/validation/adr033-c4-gate3-live-2026-10-26/probes/{}/artifact/gate-report.json"


def _core_repo() -> Path | None:
    cands = [os.environ.get("AP1_CORE_REPO"), "C:/dev/mneme", str(ROOT.parent / "mneme")]
    for c in cands:
        if c and Path(c, ".git").exists():
            probe = subprocess.run(["git", "-C", c, "cat-file", "-e", C.CORE_COMMIT + "^{commit}"],
                                   capture_output=True, check=False)
            if probe.returncode == 0:
                return Path(c)
    return None


def core_show(path: str) -> bytes:
    repo = _core_repo()
    if repo is None:
        pytest.skip("no Core checkout holding the pinned commit")
    return subprocess.run(["git", "-C", str(repo), "show", f"{C.CORE_COMMIT}:{path}"], capture_output=True,
                          check=True).stdout


@pytest.fixture(scope="session")
def core_dir(tmp_path_factory) -> str:
    d = tmp_path_factory.mktemp("core")
    for rel in C.CORE_PINS:
        data = core_show(rel)
        assert C.blob_sha1(data) == C.CORE_PINS[rel]
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return str(d)


@pytest.fixture()
def repo_root(tmp_path) -> str:
    """A stand-in lab checkout: the real gate workflow plus a dummy manifest."""
    gate = tmp_path / C.GATE_PATH
    gate.parent.mkdir(parents=True)
    gate.write_bytes((ROOT / C.GATE_PATH).read_bytes())
    (tmp_path / "ap1").mkdir()
    (tmp_path / "ap1" / "PINS.sha256").write_text("0" * 64 + "  ap1/common.py\n", encoding="ascii", newline="\n")
    return str(tmp_path)


def report(name: str) -> dict:
    return json.loads(core_show(REPORT_PATH.format(name)))


def make_zip(entries, *, dup=False) -> bytes:
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in entries:
                zi = zipfile.ZipInfo(name)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(zi, data)
    return buf.getvalue()


class FakeApi:
    """GET-only stand-in for common.Api. Routes map a path to (status, obj) or a callable(params)."""

    def __init__(self, routes: dict, archive: bytes | None = None) -> None:
        self.routes = routes
        self.archive = archive
        self.calls: list[str] = []

    def get(self, path, params=None):
        self.calls.append(path)
        assert path.startswith(("/repos/", "/users/"))
        r = self.routes.get(path, (404, None))
        if callable(r):
            r = r(params or {})
        return copy.deepcopy(r)

    def download(self, path, cap=C.ZIP_CAP):
        self.calls.append(path)
        if self.archive is None:
            raise C.Reject("ARCHIVE_UNAVAILABLE")
        return self.archive


class World:
    """One consistent synthetic world: a gate run for a PR, plus this publisher run."""

    GATE, OWN, PR, WF, BOT, ART = 5550001, 7770001, 7, 4242, 99, 313131
    T_START, T_MADE, T_END = "2026-11-24T10:00:00Z", "2026-11-24T10:00:20Z", "2026-11-24T10:00:30Z"

    def __init__(self, rep: dict, repo_root: str) -> None:
        self.rep = rep
        self.head, self.base = rep["head_sha"], rep["base_sha"]
        with open(os.path.join(repo_root, C.GATE_PATH), "rb") as fh:
            self.blob = C.blob_sha1(fh.read())
        self.conclusion = rep["disposition"]
        self.zip = make_zip([("gate-report.json", json.dumps(rep, indent=2).encode()), ("summary.md", b"# s\n")])
        self.art_name = f"mneme-gate-pr{self.PR}-{self.GATE}"
        self.run = {"id": self.GATE, "repository": {"id": C.REPO_ID}, "workflow_id": self.WF, "path": C.GATE_PATH,
                    "event": C.GATE_EVENT, "status": "completed", "conclusion": self.conclusion, "run_number": 12,
                    "run_attempt": 1, "head_sha": self.head, "head_repository": {"id": C.REPO_ID}}
        self.job = {"name": C.GATE_JOB, "id": 9001, "run_id": self.GATE, "head_sha": self.head,
                    "status": "completed", "run_attempt": 1, "conclusion": self.conclusion,
                    "steps": [{"number": 1, "name": C.EVAL_STEP, "conclusion": "success"},
                              {"number": 2, "name": "Preserve the gate evidence", "conclusion": "success",
                               "started_at": self.T_START, "completed_at": self.T_END},
                              {"number": 3, "name": "Gate decision", "conclusion": self.conclusion}]}
        self.pull = {"number": self.PR, "state": "open",
                     "base": {"repo": {"id": C.REPO_ID}, "ref": "main", "sha": self.base},
                     "head": {"repo": {"id": C.REPO_ID}, "sha": self.head}}
        self.art = {"id": self.ART, "name": self.art_name, "size_in_bytes": len(self.zip), "expired": False,
                    "digest": "sha256:" + hashlib.sha256(self.zip).hexdigest(), "created_at": self.T_MADE,
                    "workflow_run": {"id": self.GATE, "repository_id": C.REPO_ID, "head_sha": self.head,
                                     "head_repository_id": C.REPO_ID}}
        self.own = {"id": self.OWN, "head_sha": self.head, "head_branch": "feat/x", "event": "workflow_run",
                    "path": C.PUBLISHER_PATH, "run_attempt": 1, "workflow_id": 4343, "run_number": 3}
        self.comments: list = []
        self.other_runs = [{"id": self.GATE, "run_number": 12, "run_attempt": 1}]
        self.env = {"GITHUB_RUN_ID": str(self.OWN), "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "workflow_run",
                    "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "a" * 40, "GATE_RUN_ID": str(self.GATE)}

    def api(self) -> FakeApi:
        R_ = f"/repos/{C.REPO}"
        routes = {
            f"{R_}/actions/runs/{self.OWN}": (200, self.own),
            f"{R_}/actions/runs/{self.GATE}": (200, self.run),
            f"{R_}/actions/runs/{self.GATE}/jobs": (200, {"jobs": [self.job]}),
            f"{R_}/commits/{self.head}/pulls": (200, [self.pull]),
            f"{R_}/pulls/{self.PR}": (200, self.pull),
            f"{R_}/git/ref/heads/main": (200, {"object": {"sha": self.base}}),
            f"{R_}/actions/runs/{self.GATE}/artifacts": (200, {"artifacts": [self.art]}),
            f"{R_}/actions/variables/{C.VARIABLE_NAME}": (403, None),
            f"{R_}/issues/{self.PR}/comments": (200, self.comments),
            f"{R_}/actions/workflows/{C.GATE_FILE}": (200, {"id": self.WF}),
            f"{R_}/actions/workflows/{self.WF}/runs": (200, {"workflow_runs": self.other_runs}),
            f"{R_}/contents/{C.GATE_PATH}": (200, {"sha": self.blob}),
            "/users/mneme-ap1-lab-publisher%5Bbot%5D": (200, {"id": self.BOT, "login": C.BOT_LOGIN, "type": "Bot"}),
        }
        return FakeApi(routes, self.zip)


@pytest.fixture()
def world(repo_root):
    return World(report("L5"), repo_root)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")
