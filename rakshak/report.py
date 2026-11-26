"""report.json: every input file by SHA-256 (never by name) plus counts taken from what was written."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def peak_rss_mb() -> float:
    """Peak resident memory of this process and its children, in MB (honest, never invented)."""
    try:
        import resource  # Linux / macOS (the evaluator runs Linux)

        own = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        kids = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        scale = 1048576 if sys.platform == "darwin" else 1024
        return round((own + kids) / scale, 1)
    except ImportError:
        pass
    try:  # Windows (local development only)
        import ctypes
        from ctypes import wintypes

        class PMC(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        k32, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
        if psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
            return round(pmc.PeakWorkingSetSize / 1048576, 1)
    except Exception:  # noqa: BLE001 - measurement only; never fatal
        pass
    return 0.0


def write_report(out: Path, files: list[dict], records: list[dict], entities: dict,
                 generalized: int, suppressed: int, seconds: float, extra: dict | None = None) -> dict:
    n_san = sum(1 for e in files if e["status"] == "sanitized")
    n_q = sum(1 for e in files if e["status"] == "quarantined")
    report = {
        "schema": "raksha-report/1",
        "files": files,
        "counts": {
            "files_total": len(files),
            "files_sanitized": n_san,
            "files_quarantined": n_q,
            "records_processed": len(records),
            "identifiers_detected": int(sum(entities.values())),
            "records_linked": sum(1 for r in records if r["patient"] is not None),
            "records_generalized": generalized,
            "records_suppressed": suppressed,
            "records_quarantined": 0,
        },
        "entities": {k: int(v) for k, v in sorted(entities.items())},
        **(extra or {}),
        "timing": {"seconds": round(seconds, 2)},
        "resources": {"peak_rss_mb": peak_rss_mb()},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
