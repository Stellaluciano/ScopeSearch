# ScopeSearch Architecture

- API creates scan jobs and query endpoints.
- Redis queue decouples API and workers.
- Worker performs DNS, port, HTTP, TLS checks and writes snapshots/findings.
- Dashboard uses API for statistics and search.
