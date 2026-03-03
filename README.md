# ScopeSearch

ScopeSearch is an **authorized-only** attack surface discovery and exposure monitoring platform for assets you own or have explicit permission to test.

## Safety First
- Scope is required in `scope.yml`.
- API and worker both enforce scope and reject out-of-scope targets.
- No exploit generation, brute-force login, or offensive capability is implemented.
- Banner in UI: **Only scan assets you own or are authorized to test.**

See `DISCLAIMER.md`, `ACCEPTABLE_USE.md`, and `SAFETY_DESIGN.md`.

## Architecture
- `web`: Next.js + TypeScript + Tailwind dashboard/search
- `api`: FastAPI ingestion/search/dashboard endpoints
- `worker`: Async Python scan worker
- `postgres`: asset/service/findings data and snapshots
- `redis`: queue for scan jobs

## Run Locally
```bash
docker compose up --build
```

- Web: http://localhost:3000
- API: http://localhost:8000/docs

## Example `scope.yml`
```yaml
domains:
  - example.com
cidr:
  - 93.184.216.0/24
```

## MVP Features
- DNS discovery for scoped domains
- Port checks (80, 443, 22, 3389, 5432, 6379, 9200)
- HTTP metadata scan (status, title, headers)
- TLS metadata scan (issuer, expiry, SAN, protocol support)
- Findings generation and scan snapshots
- Change tracking (`new_services`, `disappeared_services`)
- PostgreSQL-backed query API with basic full text search
