"""PII-free logging.

stdout, stderr, logs/, TMPDIR and HOME are all scanned for personal data by the evaluator.
This module is the ONLY place that writes to stdout/stderr, and it only accepts a fixed
message code plus integer/enum values. File names and file content are never logged.
"""
from __future__ import annotations

import sys

_ALLOWED = {
    "summary": "files {files} sanitized {sanitized} quarantined {quarantined} records {records} linked {linked}",
    "fatal": "fatal error ({kind}); no complete release was produced",
    "no_secret": "RAKSHA_SECRET is not set; refusing to run without a key",
    "model_unavailable": "optional model unavailable; continuing rules-only",
}


def _safe(v) -> str:
    if isinstance(v, bool) or isinstance(v, int):
        return str(int(v))
    if isinstance(v, float):
        return f"{v:.2f}"
    s = str(v)
    # enum-like values only: identifier characters, short. Anything else is dropped.
    return s if (s.replace("_", "").isalnum() and s.isascii() and len(s) <= 40) else "redacted"


def emit(code: str, stream=None, **values) -> None:
    template = _ALLOWED.get(code)
    if template is None:
        return
    try:
        msg = template.format(**{k: _safe(v) for k, v in values.items()})
    except (KeyError, IndexError):
        msg = code
    print(msg, file=stream or sys.stdout, flush=True)


def error_kind(exc: BaseException) -> str:
    """Exception -> class name only. str(exc) can embed raw file content, so it is never used."""
    return type(exc).__name__
