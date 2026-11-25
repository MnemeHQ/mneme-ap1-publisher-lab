"""Shared helpers for the AP1 B2.1 lab bootstrap (stdlib only, read-only, no secrets).

Everything the resolver and the canary writer have in common: trusted
constants, strict validators, a size-capped GET-only GitHub client, an
in-memory archive inspector, the identity checks for the producer gate run, and
the fixed-format writers for outputs, summary and evidence.

Nothing in this module writes to GitHub. The token (``GITHUB_TOKEN``, read-only
permissions) is only ever placed in the Authorization header of a request to
api.github.com and is never printed, stored or put in an artifact.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any, Callable

# ── trusted constants (this file is verified against ap1/PINS.sha256) ────────

REPO = "MnemeHQ/mneme-ap1-publisher-lab"
REPO_ID = 1471525560
DEFAULT_BRANCH = "main"
CORE_COMMIT = "39ab6a59ecd015f0dfa4c79eae9634770511f4bf"
CORE_PINS = {  # path -> git blob id (mode is always 100644)
    "scripts/ci/render_pr_feedback.py": "7317b2901222d9c3d42adbeb7daa83f6726fd1be",
    "scripts/ci/publish_pr_feedback.py": "b38df72097741958c5ef63533ba57ae71568887f",
}
GATE_FILE = "mneme-trusted-gate.yml"
GATE_PATH = ".github/workflows/" + GATE_FILE
GATE_WORKFLOW_NAME = "Mneme trusted gate"
GATE_JOB = "mneme trusted gate"
GATE_EVENT = "pull_request_target"
EVAL_STEP = "Evaluate the PR in the trusted workspace"
PUBLISHER_PATH = ".github/workflows/ap1-feedback-publisher.yml"
PUBLISHER_NAMES = ["Mneme AP1 feedback publisher", "AP1 feedback resolve", "AP1 feedback write"]
ENVIRONMENT = "ap1-publisher-lab"
BOT_LOGIN = "mneme-ap1-lab-publisher[bot]"
MARKER = "mneme-ap1-feedback:v1"
MARKER_LINE = "<!-- " + MARKER + " -->"
VARIABLE_NAME = "MNEME_CI_AVAILABILITY"
# Pins of the gate workflow (tests assert these equal the workflow file's env).
ADAPTER_SHA256 = "afe1d69c1ce4170875989c5866bb2ec7b5089fc895efa699ced826317e3777f9"
EVALUATOR_COMMIT = "0b74d410b45e7b3efcf08d00ce58e7bd7017b757"
EVALUATOR_WHEEL_SHA256 = "e3fcc769c440ed232ad05117f256739daf233e0c9f6d3d46586adc0de9b48c51"
VIOLATION_MODE = "strict"
# Expected availability posture used ONLY for the policy-excluded dry run (the
# variable itself is unreadable with GITHUB_TOKEN; the writer proves it later).
DRYRUN_POSTURE = "open"
DRYRUN_POLICY_VERSION = "ap1-b21-policy-unverified"

PINS_FILE = "ap1/PINS.sha256"
API = "https://api.github.com"
REDIRECT_SUFFIXES = (".blob.core.windows.net", ".githubusercontent.com")
TIMEOUT = 20
JSON_CAP = 4 * 1024 * 1024
ZIP_CAP = 1024 * 1024
ZIP_UNCOMPRESSED_CAP = 1024 * 1024
ZIP_MAX_ENTRIES = 8
EVIDENCE_CAP = 16 * 1024
MAX_PAGES = 10

DEC_RE = re.compile(r"[1-9][0-9]{0,19}")
DEC0_RE = re.compile(r"(0|[1-9][0-9]{0,19})")
SHA40_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
TOKEN_RE = re.compile(r"[A-Za-z0-9._/:@-]{0,100}")
KEY_RE = re.compile(r"[a-z0-9_]{1,48}")
LOG_RE = re.compile(r"[A-Za-z0-9 ._:=/@-]{0,200}")
ARTIFACT_NAME_RE = re.compile(r"mneme-gate-pr([1-9][0-9]{0,9})-([1-9][0-9]{0,19})")
ACTIONS = ("NO_WRITE", "CREATE", "UPDATE", "NOOP", "UNAVAILABLE", "CONFLICT")


class Reject(Exception):
    """A fixed-code fail-closed rejection. ``code`` is an UPPER_SNAKE token."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(cond: Any, code: str) -> None:
    if not cond:
        raise Reject(code)


# ── validators ───────────────────────────────────────────────────────────────

def dec(value: Any, code: str = "BAD_DECIMAL") -> str:
    require(isinstance(value, str) and DEC_RE.fullmatch(value) is not None, code)
    return value


def is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def dig(d: Any, *keys: str) -> Any:
    for k in keys:
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def safe_token(value: Any) -> str:
    """A value that may be recorded: a short token of safe characters, else a marker."""
    if isinstance(value, str) and TOKEN_RE.fullmatch(value) is not None and "::" not in value:
        return value
    return "INVALID"


def log(message: str) -> None:
    """Fixed messages and validated ids only. Anything else is redacted."""
    ok = LOG_RE.fullmatch(message) is not None and "::" not in message
    print(message if ok else "LOG_REDACTED", flush=True)


# ── strict JSON ──────────────────────────────────────────────────────────────

def _no_dups(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def _no_const(_name: str) -> Any:
    raise ValueError("non-finite number")


def strict_json(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_no_dups, parse_constant=_no_const)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise Reject("BAD_JSON") from None


# ── GitHub client (GET only) ─────────────────────────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class Api:
    """GET-only client for api.github.com with a byte cap on every response."""

    def __init__(self, token: str, opener: Any = None) -> None:
        require(isinstance(token, str) and token != "", "NO_TOKEN")
        self._token = token
        self._opener = opener or urllib.request.build_opener(_NoRedirect)

    def _fetch(self, url: str, headers: dict[str, str], cap: int) -> tuple[int, Any, bytes]:
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            resp = self._opener.open(req, timeout=TIMEOUT)
            status = resp.status
        except urllib.error.HTTPError as err:
            resp, status = err, err.code
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            raise Reject("NETWORK") from None
        try:
            data = resp.read(cap + 1)
            hdrs = resp.headers
        except (OSError, TimeoutError):
            raise Reject("NETWORK") from None
        finally:
            resp.close()
        require(len(data) <= cap, "RESPONSE_TOO_LARGE")
        return status, hdrs, data

    def _auth(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self._token, "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "ap1-lab-bootstrap"}

    def get(self, path: str, params: dict[str, Any] | None = None) -> tuple[int, Any]:
        """(HTTP status, parsed JSON or None). Non-2xx bodies are never parsed or kept."""
        require(path.startswith(("/repos/", "/users/")), "BAD_PATH")
        url = API + path + ("?" + urllib.parse.urlencode(params) if params else "")
        status, _hdrs, data = self._fetch(url, self._auth(), JSON_CAP)
        if 200 <= status < 300:
            return status, strict_json(data)
        return status, None

    def download(self, path: str, cap: int = ZIP_CAP) -> bytes:
        """Artifact archive bytes. The signed redirect target is fetched WITHOUT credentials."""
        require(path.startswith("/repos/") and path.endswith("/zip"), "BAD_PATH")
        status, hdrs, data = self._fetch(API + path, self._auth(), 64 * 1024)
        if status == 200:
            raise Reject("UNEXPECTED_INLINE_ARCHIVE")
        require(status in (301, 302, 303, 307, 308), "ARCHIVE_UNAVAILABLE")
        loc = hdrs.get("Location") if hdrs is not None else None
        require(isinstance(loc, str) and len(loc) <= 4096, "ARCHIVE_REDIRECT")
        parts = urllib.parse.urlsplit(loc)
        host = parts.hostname or ""
        require(parts.scheme == "https" and parts.port in (None, 443) and parts.username is None
                and any(host.endswith(s) for s in REDIRECT_SUFFIXES), "ARCHIVE_REDIRECT")
        status, _h, body = self._fetch(loc, {"User-Agent": "ap1-lab-bootstrap"}, cap)
        require(status == 200, "ARCHIVE_UNAVAILABLE")
        return body


def paged(api: Any, path: str, params: dict[str, Any], key: str | None = None) -> tuple[list[Any], bool, int]:
    """All pages of a list endpoint: (items, complete, first HTTP status). Never raises on HTTP errors."""
    items: list[Any] = []
    first = 0
    for page in range(1, MAX_PAGES + 1):
        status, obj = api.get(path, dict(params, per_page=100, page=page))
        if page == 1:
            first = status
        if obj is None:
            return items, False, first
        chunk = obj.get(key) if key and isinstance(obj, dict) else obj
        if not isinstance(chunk, list):
            return items, False, first
        items.extend(chunk)
        if len(chunk) < 100:
            return items, True, first
    return items, False, first


# ── archive inspection (in memory, nothing is extracted) ─────────────────────

def inspect_zip(data: bytes) -> list[str]:
    """Reject zip-slip, duplicate names, odd entries and oversized archives. Returns the names."""
    require(len(data) <= ZIP_CAP and data[:4] == b"PK\x03\x04", "ZIP_BAD")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        raise Reject("ZIP_BAD") from None
    require(0 < len(infos) <= ZIP_MAX_ENTRIES, "ZIP_ENTRIES")
    names = [i.filename for i in infos]
    for n in names:
        require(not (n.startswith("/") or "\\" in n or "/" in n or ".." in n or ":" in n or "\x00" in n),
                "ZIP_SLIP")
        require(re.fullmatch(r"[A-Za-z0-9._-]{1,100}", n) is not None, "ZIP_NAME")
    require(len({n.casefold() for n in names}) == len(names), "ZIP_DUPLICATE")
    total = 0
    for i in infos:
        require(not i.is_dir() and not i.flag_bits & 0x1, "ZIP_ENTRY")
        total += i.file_size
    require(total <= ZIP_UNCOMPRESSED_CAP, "ZIP_TOO_BIG")
    return names


# ── time normalization for the planner (UTC, whole seconds) ──────────────────

def utc_seconds(value: Any, *, ceil: bool) -> str | None:
    import datetime
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        dt = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    dt = dt.astimezone(datetime.timezone.utc)
    if ceil and dt.microsecond:
        dt += datetime.timedelta(seconds=1)
    return dt.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── identity of the producer gate run ────────────────────────────────────────

def _pr_head_ok(pull: Any, head: str) -> bool:
    return (is_int(dig(pull, "number")) and dig(pull, "state") == "open"
            and dig(pull, "base", "repo", "id") == REPO_ID and dig(pull, "base", "ref") == DEFAULT_BRANCH
            and dig(pull, "head", "sha") == head and dig(pull, "head", "repo", "id") == REPO_ID)


def gate_context(api: Any, run_id: str) -> dict[str, Any]:
    """Re-fetch and verify the producer gate run, its job, its pull request and the base freshness.

    Raises Reject with a fixed code on any doubt. The returned dict holds raw API
    objects for the planner; callers must record only sanitized facts.
    """
    dec(run_id)
    st, run = api.get(f"/repos/{REPO}/actions/runs/{run_id}")
    require(st == 200 and isinstance(run, dict), "GATE_RUN_UNREADABLE")
    require(run.get("id") == int(run_id), "GATE_RUN_ID")
    require(dig(run, "repository", "id") == REPO_ID, "GATE_REPO")
    require(run.get("path") == GATE_PATH, "GATE_PATH")
    require(run.get("event") == GATE_EVENT, "GATE_EVENT")
    require(is_int(run.get("run_attempt")) and run["run_attempt"] == 1, "GATE_ATTEMPT")
    require(run.get("status") == "completed", "GATE_STATUS")
    head = run.get("head_sha")
    require(isinstance(head, str) and SHA40_RE.fullmatch(head) is not None, "GATE_HEAD")
    require(is_int(run.get("run_number")) and run["run_number"] > 0 and is_int(run.get("workflow_id")), "GATE_RUN_SHAPE")
    require(dig(run, "head_repository", "id") == REPO_ID, "GATE_FORK")

    st, jobs_obj = api.get(f"/repos/{REPO}/actions/runs/{run_id}/jobs", {"per_page": 100, "filter": "latest"})
    require(st == 200 and isinstance(jobs_obj, dict) and isinstance(jobs_obj.get("jobs"), list), "GATE_JOBS")
    jobs = jobs_obj["jobs"]
    named = [j for j in jobs if isinstance(j, dict) and j.get("name") == GATE_JOB]
    require(len(named) == 1, "GATE_JOB")
    job = named[0]
    require(job.get("run_id") == run["id"] and job.get("head_sha") == head and job.get("run_attempt") == 1, "GATE_JOB")
    steps = [s for s in job.get("steps") or [] if isinstance(s, dict) and s.get("name") == EVAL_STEP]
    require(len(steps) == 1, "GATE_EVAL_STEP")

    st, lst = api.get(f"/repos/{REPO}/commits/{head}/pulls", {"per_page": 100})
    require(st == 200 and isinstance(lst, list), "PR_LOOKUP")
    open_same_head = [p for p in lst if isinstance(p, dict) and p.get("state") == "open"
                      and dig(p, "head", "sha") == head]
    require(len(open_same_head) != 0, "PR_NONE")
    require(len(open_same_head) == 1, "PR_AMBIGUOUS")
    number = open_same_head[0].get("number")
    require(is_int(number) and number > 0, "PR_SHAPE")
    st, pull = api.get(f"/repos/{REPO}/pulls/{number}")
    require(st == 200 and _pr_head_ok(pull, head) and pull["number"] == number, "PR_MISMATCH")

    st, ref = api.get(f"/repos/{REPO}/git/ref/heads/{DEFAULT_BRANCH}")
    tip = dig(ref, "object", "sha")
    require(st == 200 and isinstance(tip, str) and SHA40_RE.fullmatch(tip) is not None, "BASE_UNPROVEN")
    require(dig(pull, "base", "sha") == tip, "BASE_MOVED")
    return {"run": run, "jobs": jobs, "job": job, "eval_step": steps[0], "pull": pull, "ref": ref,
            "head_sha": head, "base_sha": tip, "pr": number}


# ── fixed-format writers ─────────────────────────────────────────────────────

OUTPUT_RULES: dict[str, Callable[[str], bool]] = {
    "action": lambda v: v in ACTIONS,
    "write_candidate": lambda v: v in ("true", "false"),
    "pr": lambda v: DEC0_RE.fullmatch(v) is not None,
    "gate_run": lambda v: DEC0_RE.fullmatch(v) is not None,
    "manifest_sha256": lambda v: SHA256_RE.fullmatch(v) is not None,
}


def format_outputs(values: dict[str, str]) -> str:
    """The exact text to append to GITHUB_OUTPUT. Fixed keys, validated single-line values."""
    require(set(values) == set(OUTPUT_RULES), "OUTPUT_KEYS")
    lines = []
    for key in OUTPUT_RULES:
        v = values[key]
        require(isinstance(v, str) and OUTPUT_RULES[key](v), "OUTPUT_VALUE")
        lines.append(f"{key}={v}\n")
    return "".join(lines)


def write_outputs(path: str, values: dict[str, str]) -> None:
    text = format_outputs(values)
    with open(path, "a", encoding="ascii", newline="\n") as fh:
        fh.write(text)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sanitize(obj: Any, depth: int = 0) -> Any:
    """Evidence-safe copy: ids, enums, shas, flags and short safe tokens only."""
    require(depth <= 6, "EVIDENCE_DEPTH")
    if obj is None or isinstance(obj, bool) or is_int(obj):
        return obj
    if isinstance(obj, str):
        return safe_token(obj)
    if isinstance(obj, list):
        require(len(obj) <= 32, "EVIDENCE_LIST")
        return [sanitize(v, depth + 1) for v in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            require(isinstance(k, str) and KEY_RE.fullmatch(k) is not None, "EVIDENCE_KEY")
            out[k] = sanitize(v, depth + 1)
        return out
    raise Reject("EVIDENCE_TYPE")


def evidence_bytes(obj: dict[str, Any]) -> bytes:
    try:
        data = (json.dumps(sanitize(obj), sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode("ascii")
        require(len(data) <= EVIDENCE_CAP, "EVIDENCE_SIZE")
        return data
    except Reject as err:
        return (json.dumps({"schema": "ap1.evidence.v1", "evidence_error": safe_token(err.code)},
                           sort_keys=True) + "\n").encode("ascii")


def write_evidence(path: str, obj: dict[str, Any]) -> None:
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(evidence_bytes(obj))


def blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()  # noqa: S324 - git object id, not security
