"""Zoltra SAST image entrypoint: scan the mounted checkout, emit one bounded artifact.

Runs inside ghcr.io/pepbunny/zoltra-opengrep-sast with /scan mounted
read-only (the exact expected commit) and /out writable. Emits exactly
one artifact file:

    /out/zoltra-sast-{request_id}.json

with schema_version 1, status findings|clean|partial, at most 500
sanitized matches, and no raw engine keys, snippets, or metavariables.
Exit 0 whenever the bounded artifact was written (findings/clean/partial);
exit 1 on any other failure (missing artifact -> backend `not_scanned`).

Stdlib only. The backend re-validates every field of the artifact on
ingest and never trusts this script's output.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ENGINE_VERSION_EXPECTED = "1.29.0"
BINARY = Path("/usr/local/bin/opengrep")
RULES_PATH = Path("/opt/zoltra-sast/rules.yml")
SCAN_ROOT = Path("/scan")
OUT_DIR = Path("/out")

MAX_RAW_BYTES = 1048576  # exact 1 MiB raw-engine cap (launcher parity)
MAX_MATCHES = 500  # exact 500-match cap (launcher parity)

SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,100}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

ALLOWED_TOP_KEYS = frozenset({
    "schema_version", "request_id", "repository", "commit",
    "status", "match_count", "matches",
})
ALLOWED_MATCH_KEYS = frozenset({"path", "line", "rule_id", "message", "severity"})
MAX_PATH_LEN = 500
MAX_MESSAGE_LEN = 500
MAX_RULE_ID_LEN = 120
MAX_SEVERITY_LEN = 20


def _env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        print(f"sast-entrypoint: missing {name}", file=sys.stderr)  # noqa: T201
        raise SystemExit(1)
    return value


def _load_allowed_rules() -> dict[str, str]:
    import yaml

    text = RULES_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    rules = data.get("rules") if isinstance(data, dict) else None
    allowed: dict[str, str] = {}
    for rule in rules or []:
        if not isinstance(rule, dict):
            continue
        rule_id = rule.get("id")
        message = rule.get("message", "owned-rule")
        if (
            isinstance(rule_id, str)
            and rule_id.startswith("zoltra.sast.")
            and isinstance(message, str)
            and message.strip()
        ):
            allowed[rule_id] = " ".join(message.split())
    if not allowed:
        print("sast-entrypoint: rule pack has no usable rules", file=sys.stderr)  # noqa: T201
        raise SystemExit(1)
    return allowed


def _match_identity(
    raw_path: object, check_id: object, allowed: dict[str, str],
) -> tuple[str, str]:
    """Validate the path and rule id of one match."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("match malformed")
    if not isinstance(check_id, str) or check_id not in allowed:
        raise ValueError("unexpected rule id")
    return raw_path, check_id


def _match_line_severity(start: object, extra: object) -> tuple[int, str]:
    """Validate the line and severity of one match."""
    if not isinstance(start, dict) or not isinstance(start.get("line"), int):
        raise ValueError("match malformed")
    line = start["line"]
    if isinstance(line, bool) or line < 1:
        raise ValueError("match malformed")
    severity = extra.get("severity") if isinstance(extra, dict) else None
    if not isinstance(severity, str) or not severity.strip():
        raise ValueError("match malformed")
    return line, severity.strip()


def _match_scalars(
    raw_path: object, check_id: object, start: object,
    extra: object, allowed: dict[str, str],
) -> tuple[str, str, int, str]:
    """Validate the scalar match fields; fail closed on anything else."""
    path, rule_id = _match_identity(raw_path, check_id, allowed)
    line, severity = _match_line_severity(start, extra)
    return path, rule_id, line, severity


def _sanitize_match(item: object, allowed: dict[str, str]) -> dict:
    if not isinstance(item, dict):
        raise ValueError("match malformed")
    # Only the four known engine fields are read; every other engine key
    # (snippets, metavariables, fixes) is dropped here and can never
    # enter the artifact.
    raw_path = item.get("path")
    check_id = item.get("check_id")
    start = item.get("start")
    extra = item.get("extra")
    raw_path, check_id, line, severity = _match_scalars(
        raw_path, check_id, start, extra, allowed)
    candidate = Path(raw_path)
    if candidate.is_absolute():
        # The engine reports the target exactly as mounted (/scan/...).
        # Normalize against the declared scan root; anything outside it
        # (or unresolvable) stays a hard failure.
        try:
            candidate = candidate.resolve().relative_to(SCAN_ROOT.resolve())
        except (OSError, ValueError) as exc:
            raise ValueError("match outside snapshot") from exc
    if ".." in candidate.parts:
        raise ValueError("match outside snapshot")
    rel = candidate.as_posix()
    if rel in ("", "."):
        raise ValueError("match outside snapshot")
    if len(rel) > MAX_PATH_LEN:
        raise ValueError("match malformed")
    if len(check_id) > MAX_RULE_ID_LEN or len(severity.strip()) > MAX_SEVERITY_LEN:
        raise ValueError("match malformed")
    return {
        "path": rel,
        "line": line,
        "rule_id": check_id,
        "message": allowed[check_id][:MAX_MESSAGE_LEN],
        "severity": severity.strip()[:MAX_SEVERITY_LEN],
    }


def _interpret_engine_output(
    code: int, results: list, errors: list, allowed: dict[str, str],
) -> tuple[str, list]:
    """Bounded verdict from untrusted engine JSON; fail closed, never clean.

    Exit 1 is accepted only when at least one match exists; engine
    errors or over-cap output degrade to partial, never to clean.
    """
    if errors or len(results) > MAX_MATCHES:
        return "partial", []
    if code not in (0, 1):
        raise ValueError("scanner process failed")
    if code == 1 and not results:
        raise ValueError("failure without matches")
    matches = [_sanitize_match(item, allowed) for item in results]
    matches.sort(key=lambda m: (m["path"], m["line"], m["rule_id"]))
    return ("findings" if matches else "clean"), matches


def _check_engine_version() -> None:
    """The scanner binary must report the pinned engine line."""
    version = subprocess.run(
        [str(BINARY), "--version"], capture_output=True, text=True, check=False,
    )
    if version.returncode != 0 or ENGINE_VERSION_EXPECTED not in (
        f"{version.stdout} {version.stderr}"
    ):
        print("sast-entrypoint: scanner binary drift", file=sys.stderr)  # noqa: T201
        raise SystemExit(1)


def main() -> int:
    request_id, expected_sha, repository = _dispatch_env()
    return _scan_main(request_id, expected_sha, repository)


def _dispatch_env() -> tuple[str, str, str]:
    """Validate the dispatch identity; fail closed on anything else."""
    request_id = _env("ZOLTRA_REQUEST_ID")
    expected_sha = _env("ZOLTRA_EXPECTED_SHA")
    repository = _env("ZOLTRA_REPOSITORY")
    for label, valid in (
        ("request_id", REQUEST_ID_RE.fullmatch(request_id)),
        ("expected_sha", SHA_RE.fullmatch(expected_sha)),
        ("repository", REPO_RE.fullmatch(repository)),
    ):
        if not valid:
            print(f"sast-entrypoint: bad {label}", file=sys.stderr)  # noqa: T201
            raise SystemExit(1)
    assert isinstance(request_id, str)
    assert isinstance(expected_sha, str)
    assert isinstance(repository, str)
    return request_id, expected_sha, repository


def _scan_main(request_id: str, expected_sha: str, repository: str) -> int:
    allowed = _load_allowed_rules()
    _check_engine_version()

    proc = subprocess.Popen(
        [str(BINARY), "scan", "--jobs", "1", "--json",
         "-f", str(RULES_PATH), str(SCAN_ROOT)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    assert proc.stdout is not None
    raw = proc.stdout.read(MAX_RAW_BYTES + 1)
    if len(raw) > MAX_RAW_BYTES:
        # Stop draining before wait(): a full pipe with a still-writing
        # engine would deadlock the runner until the job times out.
        proc.kill()
        proc.wait()
        status, matches = "partial", []
    else:
        code = proc.wait()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            print("sast-entrypoint: scanner output malformed", file=sys.stderr)  # noqa: T201
            return 1
        if not isinstance(payload, dict):
            print("sast-entrypoint: scanner output malformed", file=sys.stderr)  # noqa: T201
            return 1
        results = payload.get("results")
        errors = payload.get("errors", [])
        if not isinstance(results, list) or not isinstance(errors, list):
            print("sast-entrypoint: scanner output malformed", file=sys.stderr)  # noqa: T201
            return 1
        try:
            status, matches = _interpret_engine_output(
                code, results, errors, allowed)
        except ValueError as exc:
            print(f"sast-entrypoint: {exc}", file=sys.stderr)  # noqa: T201
            return 1

    return _write_artifact(request_id, repository, expected_sha, status, matches)


def _write_artifact(
    request_id: str, repository: str, expected_sha: str,
    status: str, matches: list,
) -> int:
    """Emit the single bounded artifact; always exits 0.

    Findings, clean, AND partial exit 0 so the workflow's upload step
    still runs. Only a missing artifact (never written here) exits
    nonzero via the callers' failure paths, failing the job into
    `not_scanned`. The backend re-validates the status value, so an
    unexpected status here still fails closed downstream.
    """
    artifact = {
        "schema_version": 1,
        "request_id": request_id,
        "repository": repository,
        "commit": expected_sha.lower(),
        "status": status,
        "match_count": len(matches),
        "matches": matches,
    }
    out_path = OUT_DIR / f"zoltra-sast-{request_id}.json"
    out_path.write_text(json.dumps(artifact), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
