import asyncio
import hashlib
import json
from datetime import datetime, timezone

from redis import Redis
from sqlalchemy import select

from scopesearch_worker.core.config import settings
from scopesearch_worker.db.session import SessionLocal
from scopesearch_worker.models import Asset, Finding, ScanJob, ScanResult, Service
from scopesearch_worker.services.scanners import COMMON_PORTS, check_port, http_scan, resolve_domain, tls_scan
from scopesearch_worker.services.scope import ScopeError, load_scope


def make_finding(asset_id: int, scan_job_id: int, severity: str, title: str, description: str, remediation: str, evidence: dict):
    return Finding(
        asset_id=asset_id,
        scan_job_id=scan_job_id,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        evidence=evidence,
        status="open",
    )


async def process_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        db.commit()

        target = job.requested_target
        load_scope().ensure_target_allowed(target)

        ips = await resolve_domain(target)
        snapshot_data = {"target": target, "ips": ips, "services": [], "findings": []}

        for ip in ips:
            asset = db.scalar(select(Asset).where(Asset.hostname == target, Asset.ip_address == ip))
            if not asset:
                asset = Asset(domain=target, hostname=target, ip_address=ip)
                db.add(asset)
                db.commit()
                db.refresh(asset)

            previous_ports = {s.port for s in db.scalars(select(Service).where(Service.asset_id == asset.id)).all()}
            open_ports = []
            for port in COMMON_PORTS:
                is_open = await check_port(ip, port)
                await asyncio.sleep(settings.worker_rate_limit_seconds)
                if not is_open:
                    continue
                open_ports.append(port)
                service_name = "https" if port == 443 else "http" if port == 80 else "tcp"
                meta = {}
                if port == 80:
                    meta["http"] = await http_scan(target)
                if port == 443:
                    meta["http"] = await http_scan(f"{target}:443")
                    meta["tls"] = await tls_scan(target)

                service = db.scalar(select(Service).where(Service.asset_id == asset.id, Service.port == port))
                if not service:
                    service = Service(asset_id=asset.id, port=port, protocol="tcp", service_name=service_name, confidence_score=0.9, service_metadata=meta)
                    db.add(service)
                else:
                    service.service_metadata = meta
                    service.confidence_score = 0.9
                db.commit()

                snapshot_data["services"].append({"asset_id": asset.id, "ip": ip, "port": port, "metadata": meta})

                http_meta = meta.get("http", {})
                headers = {k.lower(): v for k, v in http_meta.get("headers", {}).items()}
                missing = [h for h in ["strict-transport-security", "content-security-policy", "x-frame-options"] if h not in headers]
                if missing:
                    finding = make_finding(asset.id, job.id, "medium", "Missing security headers", f"{target} is missing recommended headers.", "Set HSTS, CSP, and X-Frame-Options headers.", {"missing": missing, "port": port})
                    db.add(finding)
                    snapshot_data["findings"].append({"title": finding.title, "severity": finding.severity})
                if port not in {80, 443, 22}:
                    finding = make_finding(asset.id, job.id, "low", "Exposed service on uncommon port", f"Service exposed on port {port}.", "Review internet exposure and firewall policy.", {"port": port})
                    db.add(finding)
                    snapshot_data["findings"].append({"title": finding.title, "severity": finding.severity})

                tls_meta = meta.get("tls") or {}
                weak = [v for v in tls_meta.get("supported_tls_versions", []) if v in {"TLSv1", "TLSv1_1"}]
                if weak:
                    finding = make_finding(asset.id, job.id, "medium", "Weak TLS configuration", "Legacy TLS versions supported.", "Disable TLSv1/1.1 and allow TLSv1.2+.", {"versions": weak})
                    db.add(finding)
                    snapshot_data["findings"].append({"title": finding.title, "severity": finding.severity})

            disappeared = sorted(previous_ports - set(open_ports))
            if disappeared:
                snapshot_data.setdefault("changes", []).append({"asset_id": asset.id, "disappeared_services": disappeared})
            new_services = sorted(set(open_ports) - previous_ports)
            if new_services:
                snapshot_data.setdefault("changes", []).append({"asset_id": asset.id, "new_services": new_services})

        snapshot_id = hashlib.sha1(json.dumps(snapshot_data, sort_keys=True).encode()).hexdigest()[:16]
        db.add(ScanResult(scan_job_id=job.id, snapshot_id=snapshot_id, result_type="snapshot", data=snapshot_data))
        db.commit()

        job.status = "completed"
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
    except ScopeError:
        if job := db.get(ScanJob, job_id):
            job.status = "blocked"
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
    except Exception:
        if job := db.get(ScanJob, job_id):
            job.status = "failed"
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


async def main() -> None:
    redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    while True:
        entry = redis_client.brpop(settings.scan_queue_name, timeout=5)
        if not entry:
            await asyncio.sleep(1)
            continue
        _, job_id = entry
        await process_job(int(job_id))


if __name__ == "__main__":
    asyncio.run(main())
