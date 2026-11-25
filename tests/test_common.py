"""Unit tests for ap1/common.py: validators, outputs, archive inspection, client, identity checks."""
from __future__ import annotations

import hashlib
import io
import urllib.error

import pytest

import common as C
from conftest import World, make_zip, report

HOSTILE = [
    "::add-mask::secret", "::stop-commands::abc", "::error::boom", "line1\r\nline2",
    "x\nwrite_candidate=true", "ghadelimiter_0123456789", "ok\n::set-output name=a::b", "a" * 500,
    "‮ rtl", "`tick`", "<script>", "$(id)",
]


# ── outputs ──────────────────────────────────────────────────────────────────

GOOD = {"action": "CREATE", "write_candidate": "true", "pr": "7", "gate_run": "5550001",
        "manifest_sha256": "ab" * 32}


def test_format_outputs_fixed_keys_and_lines():
    text = C.format_outputs(GOOD)
    assert text.splitlines() == [f"{k}={GOOD[k]}" for k in ("action", "write_candidate", "pr", "gate_run",
                                                            "manifest_sha256")]
    assert text.endswith("\n") and "\r" not in text


@pytest.mark.parametrize("key,bad", [
    ("action", "create"), ("action", "BLOCK"), ("action", "NO_WRITE\nwrite_candidate=true"),
    ("write_candidate", "True"), ("write_candidate", "1"), ("pr", "-1"), ("pr", "01"), ("pr", "7\n"),
    ("gate_run", "1e5"), ("gate_run", ""), ("manifest_sha256", "AB" * 32), ("manifest_sha256", "a" * 63),
    ("manifest_sha256", "a" * 64 + "\n"),
])
def test_format_outputs_rejects_bad_values(key, bad):
    with pytest.raises(C.Reject):
        C.format_outputs(dict(GOOD, **{key: bad}))


def test_format_outputs_rejects_extra_or_missing_keys():
    with pytest.raises(C.Reject):
        C.format_outputs(dict(GOOD, extra="1"))
    with pytest.raises(C.Reject):
        C.format_outputs({k: v for k, v in GOOD.items() if k != "pr"})


@pytest.mark.parametrize("bad", HOSTILE)
def test_hostile_strings_never_validate_as_output(bad):
    for key in C.OUTPUT_RULES:
        with pytest.raises(C.Reject):
            C.format_outputs(dict(GOOD, **{key: bad}))


def test_write_outputs_appends_only_validated_text(tmp_path):
    p = tmp_path / "out"
    p.write_text("existing=1\n")
    C.write_outputs(str(p), GOOD)
    assert p.read_text().startswith("existing=1\n")
    assert "GITHUB" not in p.read_text()


# ── decimals, tokens, log, evidence ──────────────────────────────────────────

@pytest.mark.parametrize("v", ["1", "123456", "9" * 20])
def test_dec_accepts(v):
    assert C.dec(v) == v


@pytest.mark.parametrize("v", ["", "0", "01", "-1", "1 ", "1\n", "9" * 21, "١٢", None, 5, "1.0"])
def test_dec_rejects(v):
    with pytest.raises(C.Reject):
        C.dec(v)


# A bare delimiter-looking word is a plain safe token: harmless, because outputs are only ever written as
# validated key=value lines and never use the name<<delimiter form (see the output tests above).
@pytest.mark.parametrize("bad", [h for h in HOSTILE if not h.startswith("ghadelimiter")])
def test_safe_token_and_log_redact_hostile(bad, capsys):
    assert C.safe_token(bad) == "INVALID"
    C.log(bad)
    out = capsys.readouterr().out
    assert out == "LOG_REDACTED\n"


def test_log_passes_fixed_messages(capsys):
    C.log("resolve action=NO_WRITE write_candidate=false")
    assert capsys.readouterr().out == "resolve action=NO_WRITE write_candidate=false\n"


def test_evidence_sanitizes_and_is_bounded():
    data = C.evidence_bytes({"a": {"b": HOSTILE, "n": 5, "t": True, "x": None}})
    text = data.decode("ascii")
    risky = [h for h in HOSTILE if not h.startswith("ghadelimiter")]
    for bad in risky:
        assert bad not in text
    assert text.count("INVALID") == len(risky)
    huge = C.evidence_bytes({"k": [{"v": i} for i in range(32)], "z": {"y": ["q" * 100] * 32}})
    assert len(huge) <= C.EVIDENCE_CAP
    over = C.evidence_bytes({f"k{i}": ["a" * 100] * 32 for i in range(40)})
    assert len(over) <= C.EVIDENCE_CAP and b"evidence_error" in over


def test_evidence_rejects_odd_keys_and_types():
    assert b"evidence_error" in C.evidence_bytes({"Bad Key": 1})
    assert b"evidence_error" in C.evidence_bytes({"k": 1.5})


# ── archives ─────────────────────────────────────────────────────────────────

def test_zip_ok():
    z = make_zip([("gate-report.json", b"{}"), ("summary.md", b"x")])
    assert C.inspect_zip(z) == ["gate-report.json", "summary.md"]


@pytest.mark.parametrize("name", ["../evil", "a/b", "/abs", "a\\b", "..", "x:y"])
def test_zip_slip_rejected(name):
    with pytest.raises(C.Reject) as e:
        C.inspect_zip(make_zip([("gate-report.json", b"{}"), (name, b"x")]))
    assert e.value.code == "ZIP_SLIP"


def test_zip_duplicate_names_rejected():
    z = make_zip([("gate-report.json", b"{}"), ("gate-report.json", b"{}")])
    with pytest.raises(C.Reject) as e:
        C.inspect_zip(z)
    assert e.value.code == "ZIP_DUPLICATE"
    z = make_zip([("a.json", b"{}"), ("A.JSON", b"{}")])
    with pytest.raises(C.Reject) as e:
        C.inspect_zip(z)
    assert e.value.code == "ZIP_DUPLICATE"


def test_zip_caps():
    with pytest.raises(C.Reject) as e:
        C.inspect_zip(make_zip([("a.json", b"0" * (C.ZIP_UNCOMPRESSED_CAP + 1))]))
    assert e.value.code == "ZIP_TOO_BIG"
    with pytest.raises(C.Reject) as e:
        C.inspect_zip(make_zip([(f"f{i}.json", b"x") for i in range(C.ZIP_MAX_ENTRIES + 1)]))
    assert e.value.code == "ZIP_ENTRIES"
    with pytest.raises(C.Reject) as e:
        C.inspect_zip(b"PK\x03\x04" + b"\x00" * (C.ZIP_CAP + 1))
    assert e.value.code == "ZIP_BAD"


@pytest.mark.parametrize("data", [b"", b"not a zip", b"PK\x03\x04garbage"])
def test_zip_garbage_rejected(data):
    with pytest.raises(C.Reject):
        C.inspect_zip(data)


def test_zip_directory_entry_rejected():
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("d/", b"")
    with pytest.raises(C.Reject):
        C.inspect_zip(buf.getvalue())


# ── client: redirects, caps, host allowlist ──────────────────────────────────

class _Resp:
    def __init__(self, status, body=b"", headers=None):
        self.status, self._body, self.headers = status, body, headers or {}

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]

    def close(self):
        pass


class _Opener:
    def __init__(self, script):
        self.script, self.requests = list(script), []

    def open(self, req, timeout=None):
        self.requests.append(req)
        r = self.script.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def test_download_drops_credentials_on_redirect():
    op = _Opener([_Resp(302, headers={"Location": "https://pipelines.blob.core.windows.net/x?sig=1"}),
                  _Resp(200, b"PK\x03\x04zip")])
    data = C.Api("tok", opener=op).download("/repos/o/r/actions/artifacts/1/zip")
    assert data == b"PK\x03\x04zip"
    assert op.requests[0].get_header("Authorization") == "Bearer tok"
    assert op.requests[1].get_header("Authorization") is None


@pytest.mark.parametrize("loc", ["http://x.blob.core.windows.net/a", "https://evil.example.com/a",
                                 "https://a.blob.core.windows.net.evil.com/a", "https://u:p@a.blob.core.windows.net/a",
                                 "https://a.blob.core.windows.net:8443/a", "file:///etc/passwd"])
def test_download_rejects_bad_redirect_targets(loc):
    op = _Opener([_Resp(302, headers={"Location": loc})])
    with pytest.raises(C.Reject):
        C.Api("tok", opener=op).download("/repos/o/r/actions/artifacts/1/zip")
    assert len(op.requests) == 1


def test_download_size_cap_and_errors():
    op = _Opener([_Resp(302, headers={"Location": "https://a.blob.core.windows.net/a"}),
                  _Resp(200, b"x" * (C.ZIP_CAP + 1))])
    with pytest.raises(C.Reject) as e:
        C.Api("tok", opener=op).download("/repos/o/r/actions/artifacts/1/zip")
    assert e.value.code == "RESPONSE_TOO_LARGE"
    with pytest.raises(C.Reject) as e:
        C.Api("tok", opener=_Opener([urllib.error.URLError("x")])).get("/repos/o/r")
    assert e.value.code == "NETWORK"
    with pytest.raises(C.Reject):
        C.Api("")
    with pytest.raises(C.Reject):
        C.Api("tok", opener=_Opener([])).get("/orgs/x")  # only /repos and /users


def test_get_json_strict_and_non_2xx_unparsed():
    api = C.Api("tok", opener=_Opener([_Resp(200, b'{"a": 1, "a": 2}')]))
    with pytest.raises(C.Reject) as e:
        api.get("/repos/o/r")
    assert e.value.code == "BAD_JSON"
    api = C.Api("tok", opener=_Opener([_Resp(200, b'{"a": NaN}')]))
    with pytest.raises(C.Reject):
        api.get("/repos/o/r")
    api = C.Api("tok", opener=_Opener([_Resp(403, b"::error::hostile not json")]))
    assert api.get("/repos/o/r") == (403, None)


def test_paged_stops_and_flags_incomplete():
    pages = {1: [{"i": i} for i in range(100)], 2: [{"i": 1}]}
    class A:
        def get(self, path, params):
            return 200, pages[params["page"]]
    items, complete, st = C.paged(A(), "/repos/x", {})
    assert len(items) == 101 and complete and st == 200
    class B:
        def get(self, path, params):
            return 200, [{"i": 1}] * 100
    items, complete, _ = C.paged(B(), "/repos/x", {})
    assert not complete and len(items) == 100 * C.MAX_PAGES
    class D:
        def get(self, path, params):
            return 403, None
    assert C.paged(D(), "/repos/x", {}) == ([], False, 403)


def test_utc_seconds():
    assert C.utc_seconds("2026-11-24T05:00:00-05:00", ceil=False) == "2026-11-24T10:00:00Z"
    assert C.utc_seconds("2026-11-24T10:00:00.4Z", ceil=True) == "2026-11-24T10:00:01Z"
    assert C.utc_seconds("2026-11-24T10:00:00.4Z", ceil=False) == "2026-11-24T10:00:00Z"
    assert C.utc_seconds("2026-11-24T10:00:00", ceil=False) is None
    assert C.utc_seconds("garbage", ceil=False) is None


# ── gate identity ────────────────────────────────────────────────────────────

def test_gate_context_happy(world):
    ctx = C.gate_context(world.api(), str(world.GATE))
    assert ctx["pr"] == world.PR and ctx["head_sha"] == world.head and ctx["base_sha"] == world.base


def _mutate(world, fn):
    fn(world)
    return world


@pytest.mark.parametrize("code,fn", [
    ("GATE_PATH", lambda w: w.run.__setitem__("path", ".github/workflows/other.yml")),
    ("GATE_PATH", lambda w: w.run.__setitem__("path", C.GATE_PATH + "@refs/heads/x")),
    ("GATE_EVENT", lambda w: w.run.__setitem__("event", "pull_request")),
    ("GATE_EVENT", lambda w: w.run.__setitem__("event", "workflow_dispatch")),
    ("GATE_ATTEMPT", lambda w: w.run.__setitem__("run_attempt", 2)),
    ("GATE_ATTEMPT", lambda w: w.run.__setitem__("run_attempt", "1")),
    ("GATE_REPO", lambda w: w.run.__setitem__("repository", {"id": 1})),
    ("GATE_STATUS", lambda w: w.run.__setitem__("status", "in_progress")),
    ("GATE_FORK", lambda w: w.run.__setitem__("head_repository", {"id": 2})),
    ("GATE_HEAD", lambda w: w.run.__setitem__("head_sha", "XYZ")),
    ("GATE_RUN_ID", lambda w: w.run.__setitem__("id", 1)),
    ("GATE_JOB", lambda w: w.job.__setitem__("name", "mneme trusted gate 2")),
    ("GATE_JOB", lambda w: w.job.__setitem__("run_attempt", 2)),
    ("GATE_EVAL_STEP", lambda w: w.job["steps"].pop(0)),
    ("PR_MISMATCH", lambda w: w.pull["head"].__setitem__("repo", {"id": 5})),
    ("PR_MISMATCH", lambda w: w.pull["base"].__setitem__("ref", "dev")),
])
def test_gate_identity_rejections(world, code, fn):
    _mutate(world, fn)
    with pytest.raises(C.Reject) as e:
        C.gate_context(world.api(), str(world.GATE))
    assert e.value.code == code


def test_gate_two_jobs_with_same_name_rejected(world):
    api = world.api()
    api.routes[f"/repos/{C.REPO}/actions/runs/{world.GATE}/jobs"] = (200, {"jobs": [world.job, dict(world.job, id=2)]})
    with pytest.raises(C.Reject) as e:
        C.gate_context(api, str(world.GATE))
    assert e.value.code == "GATE_JOB"


def test_pr_resolution_ambiguity_and_none(world):
    api = world.api()
    p = f"/repos/{C.REPO}/commits/{world.head}/pulls"
    api.routes[p] = (200, [world.pull, dict(world.pull, number=8)])
    with pytest.raises(C.Reject) as e:
        C.gate_context(api, str(world.GATE))
    assert e.value.code == "PR_AMBIGUOUS"
    api.routes[p] = (200, [dict(world.pull, state="closed")])
    with pytest.raises(C.Reject) as e:
        C.gate_context(api, str(world.GATE))
    assert e.value.code == "PR_NONE"
    api.routes[p] = (200, [])
    with pytest.raises(C.Reject) as e:
        C.gate_context(api, str(world.GATE))
    assert e.value.code == "PR_NONE"
    api.routes[p] = (403, None)
    with pytest.raises(C.Reject) as e:
        C.gate_context(api, str(world.GATE))
    assert e.value.code == "PR_LOOKUP"


def test_closed_pr_with_other_open_pr_same_head_still_ambiguous(world):
    api = world.api()
    api.routes[f"/repos/{C.REPO}/commits/{world.head}/pulls"] = (
        200, [world.pull, dict(world.pull, number=9, base={"repo": {"id": 3}, "ref": "main", "sha": world.base})])
    with pytest.raises(C.Reject) as e:
        C.gate_context(api, str(world.GATE))
    assert e.value.code == "PR_AMBIGUOUS"


def test_base_moved_and_unproven(world):
    api = world.api()
    api.routes[f"/repos/{C.REPO}/git/ref/heads/main"] = (200, {"object": {"sha": "f" * 40}})
    with pytest.raises(C.Reject) as e:
        C.gate_context(api, str(world.GATE))
    assert e.value.code == "BASE_MOVED"
    api.routes[f"/repos/{C.REPO}/git/ref/heads/main"] = (404, None)
    with pytest.raises(C.Reject) as e:
        C.gate_context(api, str(world.GATE))
    assert e.value.code == "BASE_UNPROVEN"


def test_gate_context_rejects_bad_run_id(world):
    for v in ("", "0", "1\n", "abc"):
        with pytest.raises(C.Reject):
            C.gate_context(world.api(), v)


def test_trusted_constants_match_the_gate_workflow():
    import re
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / C.GATE_PATH).read_text(encoding="utf-8")
    env = dict(re.findall(r"^  ([A-Z0-9_]+): ([0-9a-fA-F]{40,64}|strict)$", text, re.M))
    assert env["EVALUATOR_COMMIT"] == C.EVALUATOR_COMMIT
    assert env["APPROVED_WHEEL_SHA256"] == C.EVALUATOR_WHEEL_SHA256
    assert env["ADAPTER_SHA256"] == C.ADAPTER_SHA256
    assert env["VIOLATION_MODE"] == C.VIOLATION_MODE
    assert re.search(r"^name: " + re.escape(C.GATE_WORKFLOW_NAME) + r"$", text, re.M)
    assert re.search(r"^    name: " + re.escape(C.GATE_JOB) + r"$", text, re.M)
    assert hashlib.sha256(b"").hexdigest()  # sanity: hashlib available
