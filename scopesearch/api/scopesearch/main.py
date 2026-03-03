from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException
from redis import Redis
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from scopesearch.core.config import settings
from scopesearch.db.base import Base
from scopesearch.db.session import engine, get_db
from scopesearch.models import Asset, Finding, ScanJob, Service
from scopesearch.schemas.scan import DashboardStats, ScanJobResponse, ScanRequest, SearchResponse
from scopesearch.services.scope import ScopeError, load_scope

app = FastAPI(title="ScopeSearch API", version="0.1.0")
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "api"}


@app.post("/scan-jobs", response_model=ScanJobResponse)
def create_scan_job(payload: ScanRequest, db: Session = Depends(get_db)):
    try:
        load_scope().ensure_target_allowed(payload.target)
    except ScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    job = ScanJob(requested_target=payload.target, status="queued")
    db.add(job)
    db.commit()
    db.refresh(job)
    redis_client.lpush(settings.scan_queue_name, str(job.id))
    return job


@app.get("/scan-jobs")
def list_scan_jobs(db: Session = Depends(get_db)):
    jobs = db.scalars(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(25)).all()
    return jobs


@app.get("/dashboard", response_model=DashboardStats)
def dashboard(db: Session = Depends(get_db)):
    total_assets = db.scalar(select(func.count(Asset.id))) or 0
    total_services = db.scalar(select(func.count(Service.id))) or 0
    open_findings = db.scalar(select(func.count(Finding.id)).where(Finding.status == "open")) or 0

    latest_job = db.scalar(select(ScanJob).where(ScanJob.status == "completed").order_by(ScanJob.finished_at.desc()).limit(1))
    new_exposures = 0
    if latest_job:
        new_exposures = db.scalar(
            select(func.count(Finding.id)).where(Finding.scan_job_id == latest_job.id, Finding.created_at >= latest_job.started_at)
        ) or 0

    return DashboardStats(
        total_assets=total_assets,
        total_services=total_services,
        open_findings=open_findings,
        new_exposures_last_scan=new_exposures,
    )


@app.get("/search", response_model=SearchResponse)
def search(query: str, db: Session = Depends(get_db)):
    query = query.strip()
    assets: list[dict] = []
    services: list[dict] = []
    findings: list[dict] = []

    if query.startswith("port:"):
        port = int(query.split(":", 1)[1])
        rows = db.execute(
            select(Service, Asset).join(Asset, Service.asset_id == Asset.id).where(Service.port == port).limit(100)
        ).all()
        services = [
            {"service_id": s.id, "hostname": a.hostname, "ip": a.ip_address, "port": s.port, "service_name": s.service_name}
            for s, a in rows
        ]
    elif query.startswith("domain:"):
        domain = query.split(":", 1)[1]
        rows = db.scalars(select(Asset).where(Asset.domain == domain).limit(100)).all()
        assets = [{"id": a.id, "domain": a.domain, "hostname": a.hostname, "ip": a.ip_address} for a in rows]
    else:
        normalized = query.replace('title:"', "").replace('header:"', "").replace('"', "")
        fts_sql = text(
            """
            SELECT id, title, description, severity
            FROM findings
            WHERE to_tsvector('english', coalesce(title,'') || ' ' || coalesce(description,'')) @@ plainto_tsquery(:q)
            LIMIT 100
            """
        )
        results = db.execute(fts_sql, {"q": normalized}).mappings().all()
        findings = [dict(row) for row in results]

    return SearchResponse(assets=assets, services=services, findings=findings)


@app.get("/banner")
def banner():
    return {"warning": "Only scan assets you own or are authorized to test."}
