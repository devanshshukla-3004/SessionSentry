"""Analyze supplied web-session configuration evidence without network access."""
from typing import Any

SEVERITY_POINTS = {"Critical": 30, "High": 20, "Medium": 10, "Low": 4, "Info": 0}


def _finding(rule_id: str, title: str, severity: str, evidence: str, remediation: str) -> dict[str, str]:
    return {"rule_id": rule_id, "title": title, "severity": severity, "evidence": evidence, "remediation": remediation}


def analyze_assessment(data: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    cookies = data.get("cookies", [])
    config = data.get("session_config", {})
    if not isinstance(cookies, list):
        raise ValueError("'cookies' must be a list")
    if not isinstance(config, dict):
        raise ValueError("'session_config' must be an object")

    sessions = [c for c in cookies if isinstance(c, dict) and str(c.get("purpose", "session")).lower() == "session"]
    if not sessions:
        findings.append(_finding("SS-001", "No session cookie evidence supplied", "Info",
            "No cookie marked purpose=session was present.", "Supply an authorized configuration export and identify session cookies."))

    for i, cookie in enumerate(sessions, 1):
        name = str(cookie.get("name") or f"unnamed-cookie-{i}")
        if cookie.get("secure") is not True:
            findings.append(_finding("SS-101", f"Session cookie may lack Secure: {name}", "High",
                f"secure={cookie.get('secure', 'unknown')!r}", "Set Secure so the browser sends the cookie only over HTTPS."))
        if cookie.get("httpOnly") is not True:
            findings.append(_finding("SS-102", f"Session cookie may lack HttpOnly: {name}", "High",
                f"httpOnly={cookie.get('httpOnly', 'unknown')!r}", "Set HttpOnly unless client-side access is explicitly required and reviewed."))
        same_site = str(cookie.get("sameSite", "")).strip().lower()
        if same_site not in {"strict", "lax", "none"}:
            findings.append(_finding("SS-103", f"SameSite missing or unknown: {name}", "Medium",
                f"sameSite={cookie.get('sameSite', 'unknown')!r}", "Set an appropriate SameSite policy and test legitimate cross-site flows."))
        elif same_site == "none" and cookie.get("secure") is not True:
            findings.append(_finding("SS-104", f"SameSite=None without Secure: {name}", "High",
                "SameSite=None while Secure is not confirmed true.", "Use Secure with SameSite=None and verify cross-site cookie use is necessary."))

    lifecycle_rules = [
        ("rotation_on_login", "SS-201", "Session ID rotation not confirmed", "High",
         "Enable session-ID rotation after authentication and privilege changes."),
        ("logout_invalidates_session", "SS-202", "Logout invalidation not confirmed", "High",
         "Invalidate the server-side session at logout and reject the old identifier."),
    ]
    for key, rule_id, title, severity, fix in lifecycle_rules:
        if config.get(key) is not True:
            findings.append(_finding(rule_id, title, severity, f"session_config.{key}={config.get(key, 'unknown')!r}", fix))

    for key, title, maximum, rule_id in [
        ("idle_timeout_minutes", "Idle timeout missing or too long", 30, "SS-203"),
        ("absolute_timeout_minutes", "Absolute session lifetime missing or too long", 720, "SS-204"),
    ]:
        value = config.get(key)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0 or value > maximum:
            findings.append(_finding(rule_id, title, "Medium",
                f"{key}={value!r}; heuristic maximum is {maximum} minutes.",
                f"Set a suitable {key.replace('_', ' ')} for the application's risk and user experience."))

    findings.sort(key=lambda f: (-SEVERITY_POINTS[f["severity"]], f["rule_id"], f["title"]))
    score = min(100, sum(SEVERITY_POINTS[f["severity"]] for f in findings))
    label = "Critical" if score >= 80 else "High" if score >= 50 else "Medium" if score >= 20 else "Low"
    return {
        "application": str(data.get("application", "Unspecified application")),
        "data_mode": "supplied_configuration_only",
        "finding_count": len(findings),
        "risk_score": score,
        "risk_label": label,
        "score_note": "Heuristic prioritization score, not exploit probability or proof of compromise.",
        "findings": findings,
    }
