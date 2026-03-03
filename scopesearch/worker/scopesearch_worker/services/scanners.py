import asyncio
import re
import socket
import ssl
from datetime import timezone

import dns.resolver
import httpx

COMMON_PORTS = [80, 443, 22, 3389, 5432, 6379, 9200]


async def resolve_domain(domain: str) -> list[str]:
    loop = asyncio.get_running_loop()

    def _resolve() -> list[str]:
        answers = dns.resolver.resolve(domain, "A")
        return [r.to_text() for r in answers]

    try:
        return await loop.run_in_executor(None, _resolve)
    except Exception:
        return []


async def check_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def http_scan(host: str) -> dict:
    url = f"http://{host}"
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
            resp = await client.get(url)
            m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            return {
                "status_code": resp.status_code,
                "title": m.group(1).strip() if m else None,
                "server": resp.headers.get("server"),
                "headers": dict(resp.headers),
            }
    except Exception as exc:
        return {"error": str(exc)}


async def tls_scan(host: str) -> dict:
    loop = asyncio.get_running_loop()

    def _scan() -> dict:
        versions = []
        cert_data = {}
        for version in [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version
                context.maximum_version = version
                with socket.create_connection((host, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                        versions.append(version.name)
                        cert = tls_sock.getpeercert()
                        cert_data = cert_data or cert
            except Exception:
                continue
        san_entries = []
        for t, value in cert_data.get("subjectAltName", []):
            if t == "DNS":
                san_entries.append(value)
        issuer = dict(x[0] for x in cert_data.get("issuer", ())).get("organizationName")
        not_after = cert_data.get("notAfter")
        not_after_iso = None
        if not_after:
            not_after_iso = ssl.cert_time_to_seconds(not_after)
            from datetime import datetime

            not_after_iso = datetime.fromtimestamp(not_after_iso, tz=timezone.utc).isoformat()
        return {
            "issuer": issuer,
            "not_after": not_after_iso,
            "san_entries": san_entries,
            "supported_tls_versions": versions,
        }

    return await loop.run_in_executor(None, _scan)
