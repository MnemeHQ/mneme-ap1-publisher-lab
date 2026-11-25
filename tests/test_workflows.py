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
    assert jobs["write"]["permissions"] == {"actions": "read", "contents": "read", "pull-requests": "read"}
    assert jobs["write"]["environment"] == "ap1-publisher-lab"
    assert jobs["write"]["needs"] == "resolve"
    cond = jobs["write"]["if"]
    assert cond == "${{ needs.resolve.outputs.write_candidate == 'true' && github.run_attempt == '1' }}"
    assert "always()" not in cond


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
    tree = [p.relative_to(ROOT).as_posix() for d in ("ap1", ".github", ".mneme")
            for p in (ROOT / d).rglob("*") if p.is_file() and p.name != "__pycache__"]
    expected = sorted([t for t in tree if t != "ap1/PINS.sha256"]
                      + ["core/scripts/ci/render_pr_feedback.py", "core/scripts/ci/publish_pr_feedback.py"])
    assert ".mneme/project_memory.json" in expected and ".github/CODEOWNERS" in expected
    assert listed == sorted(listed) == expected


# ── D10: the pin step, executed for real against a throwaway git tree ─────────

import hashlib
import os
import shutil

BASH = shutil.which("bash") or next((p for p in ("C:/Program Files/Git/bin/bash.exe",) if os.path.exists(p)), None)
GIT_ID = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "core.autocrlf=false"]


def _git(cwd, *args):
    return subprocess.run(["git", *GIT_ID, *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def pin_script(job):
    wf = load(PUB)
    step = [s for s in wf["jobs"][job]["steps"] if str(s.get("name", "")).startswith("Verify the pins")][0]
    return step["run"]


def write_manifest(lab):
    tracked = [p for p in _git(lab, "ls-files", "--", "ap1", ".github", ".mneme").split("\n") if p != "ap1/PINS.sha256"]
    tracked += ["core/scripts/ci/render_pr_feedback.py", "core/scripts/ci/publish_pr_feedback.py"]
    lines = "".join(f"{hashlib.sha256((lab / p).read_bytes()).hexdigest()}  {p}\n" for p in sorted(tracked))
    (lab / "ap1" / "PINS.sha256").write_bytes(lines.encode("ascii"))


@pytest.fixture()
def pin_tree(tmp_path, core_dir):
    if BASH is None:
        pytest.skip("bash not available")
    lab = tmp_path / "lab"
    for d in ("ap1", ".github", ".mneme"):
        shutil.copytree(ROOT / d, lab / d, ignore=shutil.ignore_patterns("__pycache__", "PINS.sha256"))
    shutil.copytree(core_dir, lab / "core")
    _git(lab, "init", "-q")
    _git(lab / "core", "init", "-q")
    _git(lab / "core", "add", "-A")
    _git(lab / "core", "commit", "-q", "-m", "c")
    (lab / "ap1" / "PINS.sha256").write_bytes(b"")
    _git(lab, "add", "ap1", ".github", ".mneme")
    write_manifest(lab)
    _git(lab, "add", "ap1", ".github", ".mneme")
    _git(lab, "commit", "-q", "-m", "lab")
    return lab


def run_pins(lab, job="resolve"):
    env = dict(os.environ, GITHUB_SHA=_git(lab, "rev-parse", "HEAD"), CORE_COMMIT=_git(lab / "core", "rev-parse", "HEAD"),
               CORE_RENDER_BLOB=C.CORE_PINS["scripts/ci/render_pr_feedback.py"],
               CORE_PUBLISH_BLOB=C.CORE_PINS["scripts/ci/publish_pr_feedback.py"])
    return subprocess.run([BASH, "-c", pin_script(job)], cwd=lab, env=env, capture_output=True, text=True)


def recommit(lab, regen=True):
    if regen:
        write_manifest(lab)
    _git(lab, "add", "-A", "ap1", ".github", ".mneme")
    _git(lab, "commit", "-q", "-m", "next")


@pytest.mark.parametrize("job", ["resolve", "write"])
def test_pin_step_passes_on_a_clean_tree(pin_tree, job):
    r = run_pins(pin_tree, job)
    assert r.returncode == 0 and "pins verified" in r.stdout, r.stdout + r.stderr


def _fails(lab, text):
    r = run_pins(lab)
    assert r.returncode != 0 and text in r.stdout, r.stdout + r.stderr


def test_pin_step_rejects_symlink_mode(pin_tree):
    blob = _git(pin_tree, "hash-object", "-w", "--stdin") if False else subprocess.run(
        ["git", "hash-object", "-w", "--stdin"], cwd=pin_tree, input="common.py", capture_output=True, text=True).stdout.strip()
    _git(pin_tree, "update-index", "--add", "--cacheinfo", f"120000,{blob},ap1/json.py")
    _git(pin_tree, "commit", "-q", "-m", "link")
    _fails(pin_tree, "tracked file mode")


def test_pin_step_rejects_executable_mode(pin_tree):
    _git(pin_tree, "update-index", "--chmod=+x", "ap1/common.py")
    _git(pin_tree, "commit", "-q", "-m", "mode")
    _fails(pin_tree, "tracked file mode")


def test_pin_step_rejects_real_symlink_in_worktree(pin_tree):
    link = pin_tree / "ap1" / "json.py"
    try:
        os.symlink("common.py", link)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here")
    _fails(pin_tree, "non-regular entry")


@pytest.mark.parametrize("rel", ["ap1/extra.py", ".github/workflows/third.yml", ".github/extra.txt", ".mneme/x.json"])
def test_pin_step_rejects_untracked_files(pin_tree, rel):
    p = pin_tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x\n")
    _fails(pin_tree, "untracked or modified file")


def test_pin_step_rejects_modified_tracked_file(pin_tree):
    (pin_tree / "ap1" / "common.py").write_text("# changed\n")
    _fails(pin_tree, "untracked or modified file")


def test_pin_step_rejects_new_tracked_file_missing_from_manifest(pin_tree):
    (pin_tree / ".github" / "workflows" / "third.yml").write_text("name: x\n")
    recommit(pin_tree, regen=False)
    _fails(pin_tree, "manifest path set")


def test_pin_step_rejects_committed_change_without_manifest_update(pin_tree):
    (pin_tree / "ap1" / "common.py").write_text("# changed\n")
    recommit(pin_tree, regen=False)
    _fails(pin_tree, "sha256 mismatch")


def test_pin_step_covers_the_memory_file(pin_tree):
    (pin_tree / ".mneme" / "project_memory.json").write_text("{}\n")
    recommit(pin_tree, regen=False)
    _fails(pin_tree, "sha256 mismatch")


def test_pin_step_rejects_wrong_core_blob(pin_tree):
    (pin_tree / "core" / "scripts" / "ci" / "render_pr_feedback.py").write_text("# x\n")
    _git(pin_tree / "core", "commit", "-q", "-am", "x")
    _fails(pin_tree, "core file blob")
