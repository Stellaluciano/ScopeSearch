from datetime import datetime

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)


class ScanJobResponse(BaseModel):
    id: int
    requested_target: str
    status: str
    created_at: datetime


class DashboardStats(BaseModel):
    total_assets: int
    total_services: int
    open_findings: int
    new_exposures_last_scan: int


class SearchResponse(BaseModel):
    assets: list[dict]
    services: list[dict]
    findings: list[dict]
