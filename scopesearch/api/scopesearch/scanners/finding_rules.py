from datetime import datetime, timedelta, timezone


def generate_http_findings(asset_id: int, hostname: str, http_data: dict) -> list[dict]:
    findings: list[dict] = []
    missing = [h for h in ["strict-transport-security", "content-security-policy", "x-frame-options"] if h not in {k.lower(): v for k, v in (http_data.get("headers") or {}).items()}]
    if missing:
        findings.append(
            {
                "asset_id": asset_id,
                "severity": "medium",
                "title": "Missing security headers",
                "description": f"{hostname} is missing recommended security headers.",
                "remediation": "Add HSTS, CSP, and X-Frame-Options headers.",
                "evidence": {"missing_headers": missing},
            }
        )
    title = (http_data.get("title") or "").lower()
    if any(x in title for x in ["admin", "dashboard", "console"]):
        findings.append(
            {
                "asset_id": asset_id,
                "severity": "low",
                "title": "Public admin panel path",
                "description": f"Potential admin/login page discovered on {hostname}.",
                "remediation": "Restrict administrative interfaces with network controls and SSO.",
                "evidence": {"page_title": http_data.get("title")},
            }
        )
    return findings


def generate_tls_findings(asset_id: int, tls_data: dict) -> list[dict]:
    findings: list[dict] = []
    expires_at = tls_data.get("not_after")
    if expires_at:
        dt = datetime.fromisoformat(expires_at)
        if dt - datetime.now(timezone.utc) < timedelta(days=21):
            findings.append(
                {
                    "asset_id": asset_id,
                    "severity": "high",
                    "title": "TLS certificate expiration approaching",
                    "description": "Certificate expires within 21 days.",
                    "remediation": "Renew certificate and automate certificate lifecycle management.",
                    "evidence": {"not_after": expires_at},
                }
            )
    weak_versions = [v for v in tls_data.get("supported_tls_versions", []) if v in {"TLSv1", "TLSv1.1"}]
    if weak_versions:
        findings.append(
            {
                "asset_id": asset_id,
                "severity": "medium",
                "title": "Weak TLS configuration",
                "description": "Legacy TLS versions were negotiated.",
                "remediation": "Disable TLSv1.0/1.1 and enforce TLSv1.2+.",
                "evidence": {"weak_versions": weak_versions},
            }
        )
    return findings
