"""Static checks of the two workflows and the no-secret, no-write posture."""
from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

import pytest

import common as C
from conftest import core_show

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / ".github" / "workflows" / "mneme-trusted-gate.yml"
PUB = ROOT / ".github" / "workflows" / "ap1-feedback-publisher.yml"
yaml = pytest.importorskip("yaml")


def load(p):
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def test_gate_differs_from_core_only_in_comments():
    core = core_show(".github/workflows/mneme-trusted-gate.yml").decode("utf-8").split("\n")
    lab = GATE.read_text(encoding="utf-8").split("\n")
    import difflib
    changed = [l for l in difflib.unified_diff(core, lab, lineterm="", n=0) if l[:1] in "+-" and l[:3] not in ("+++", "---")]
    assert changed and all(l[1:].startswith("#") for l in changed), changed
    # and the parsed workflow is identical
    assert yaml.safe_load("\n".join(core)) == yaml.safe_load("\n".join(lab))


def test_gate_identity_preserved():
    wf = load(GATE)
    assert wf["name"] == "Mneme trusted gate"
    assert wf[True]["pull_request_target"] == {"types": ["opened", "synchronize", "reopened"], "branches": ["main"]}
    assert list(wf["jobs"]) == ["gate"] and wf["jobs"]["gate"]["name"] == "mneme trusted gate"
    assert wf["env"]["VIOLATION_MODE"] == "strict"
    assert "vars.MNEME_CI_AVAILABILITY" in wf["env"]["MNEME_CI_AVAILABILITY"]
    art = [s for s in wf["jobs"]["gate"]["steps"] if s.get("name") == "Preserve the gate evidence"][0]
    assert art["with"]["name"] == "mneme-gate-pr${{ github.event.pull_request.number }}-${{ github.run_id }}"
    assert art["with"]["retention-days"] == 90


def test_publisher_shape():
    wf = load(PUB)
    assert wf["name"] == "Mneme AP1 feedback publisher"
    assert wf[True] == {"workflow_run": {"workflows": ["Mneme trusted gate"], "types": ["completed"]}}
    assert wf["permissions"] == {}
    assert wf["concurrency"] == {"group": "ap1-feedback-publisher", "cancel-in-progress": False}
    jobs = wf["jobs"]
    assert {k: v["name"] for k, v in jobs.items()} == {"resolve": "AP1 feedback resolve", "write": "AP1 feedback write"}
    assert jobs["resolve"]["permissions"] == {"actions": "read", "contents": "read", "pull-requests": "read",
                                              "checks": "read"}
    assert "environment" not in jobs["resolve"]
    assert jobs["write"]["permissions"] == {"actions": "read", "contents": "read"}
    assert jobs["write"]["environment"] == "ap1-publisher-lab"
    assert jobs["write"]["needs"] == "resolve"
    cond = jobs["write"]["if"]
    assert "write_candidate == 'true'" in cond and "always()" not in cond


def test_names_never_resemble_the_gate():
    for n in C.PUBLISHER_NAMES:
        low = n.casefold()
        assert "trusted gate" not in low and low != C.GATE_JOB


def test_no_secrets_no_write_scopes_no_third_party_actions():
    for p in (PUB, ROOT / "ap1" / "common.py", ROOT / "ap1" / "resolve.py", ROOT / "ap1" / "write_canary.py"):
        text = p.read_text(encoding="utf-8")
        assert "secrets." not in text, p
        assert not re.search(r"(?m)^\s*[a-z-]+: write\s*$", text), p
        for bad in ("GH_TOKEN", "app-id", "private-key", "create-github-app-token", "gh api", "-X POST",
                    '"POST"', "'POST'", "method=\"PUT\"", "method=\"PATCH\"", "method=\"DELETE\""):
            assert bad not in text, (p, bad)
    uses = re.findall(r"uses: (\S+)", PUB.read_text(encoding="utf-8"))
    assert uses and all(re.fullmatch(r"actions/(checkout|upload-artifact)@[0-9a-f]{40}", u) for u in uses), uses
    gate_uses = set(re.findall(r"uses: (\S+)", GATE.read_text(encoding="utf-8")))
    assert set(uses) <= gate_uses  # the same pins Core already uses


def test_only_the_run_id_is_taken_from_the_event():
    text = PUB.read_text(encoding="utf-8")
    exprs = re.findall(r"\$\{\{\s*([^}]+?)\s*\}\}", text)
    events = {e for e in exprs if e.startswith("github.event")}
    assert events == {"github.event.workflow_run.id"}
    # no expression inside a run: block
    for block in re.findall(r"(?ms)^\s+run: \|?\n?(.*?)(?=^\s+- |\Z)", text):
        assert "${{" not in block


def test_python_is_stdlib_only_and_parses():
    import sys
    std = set(sys.stdlib_module_names) | {"common", "resolve", "write_canary"}
    for p in sorted((ROOT / "ap1").glob("*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.module:
                mods.add(n.module.split(".")[0])
        assert mods <= std, (p, mods - std)


def test_repo_files_are_lf_only():
    for p in list(ROOT.glob("ap1/*")) + list(ROOT.glob(".github/**/*")) + list(ROOT.glob("tests/*.py")):
        if p.is_file():
            assert b"\r" not in p.read_bytes(), p


def test_pins_manifest_covers_exactly_the_expected_paths_if_present():
    pins = ROOT / "ap1" / "PINS.sha256"
    if not pins.exists():
        pytest.skip("manifest is generated last")
    listed = [l.split("  ", 1)[1] for l in pins.read_text(encoding="ascii").splitlines()]
    expected = sorted([str(p.relative_to(ROOT)).replace("\\", "/") for p in (ROOT / "ap1").glob("*") if p.name != "PINS.sha256"]
                      + [".github/CODEOWNERS", ".github/workflows/ap1-feedback-publisher.yml",
                         ".github/workflows/mneme-trusted-gate.yml",
                         "core/scripts/ci/render_pr_feedback.py", "core/scripts/ci/publish_pr_feedback.py"])
    assert listed == sorted(listed) == expected
