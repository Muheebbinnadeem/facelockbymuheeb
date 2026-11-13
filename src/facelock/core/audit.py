"""
Security audit logging for FaceLock authentication events.
Logs structured events to /var/log/facelock/audit.log and system syslog.
"""

import datetime
import json
import os
import syslog
from pathlib import Path
from typing import Any, Dict, List, Optional

from facelock.constants import AUDIT_LOG_PATH


def _fallback_log_path() -> Path:
    user_log = Path.home() / ".local" / "share" / "facelock" / "audit.log"
    user_log.parent.mkdir(parents=True, exist_ok=True)
    return user_log


def log_auth_event(
    username: str,
    service: str,
    method: str,
    success: bool,
    reason: str = "",
    confidence: Optional[float] = None,
    liveness: Optional[float] = None,
    log_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Record an authentication attempt to both the JSONL audit log and syslog.
    """
    now = datetime.datetime.now(datetime.timezone.utc).astimezone()
    record: Dict[str, Any] = {
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S %z"),
        "username": username,
        "service": service,
        "method": method,
        "status": "SUCCESS" if success else "FAILURE",
        "reason": reason,
        "pid": os.getpid(),
    }
    if confidence is not None:
        record["confidence"] = round(float(confidence), 4)
    if liveness is not None:
        record["liveness"] = round(float(liveness), 4)

    # Send to syslog
    try:
        prio = syslog.LOG_INFO if success else syslog.LOG_WARNING
        msg = (
            f"facelock[{os.getpid()}]: {record['status']} user={username} "
            f"service={service} method={method} reason='{reason}'"
        )
        syslog.openlog("facelock", syslog.LOG_PID, syslog.LOG_AUTH)
        syslog.syslog(prio, msg)
    except Exception:
        pass

    target = log_path or AUDIT_LOG_PATH
    line = json.dumps(record, ensure_ascii=False) + "\n"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(line)
    except PermissionError:
        fb = _fallback_log_path()
        with open(fb, "a", encoding="utf-8") as fh:
            fh.write(line)

    return record


def read_recent_events(limit: int = 100, log_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Return the most recent audit records in reverse chronological order.
    """
    events: List[Dict[str, Any]] = []
    candidates = [log_path] if log_path else [AUDIT_LOG_PATH, _fallback_log_path()]

    for path in candidates:
        if path and path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
                for line in lines[-limit:]:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            except Exception:
                continue

    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return events[:limit]
