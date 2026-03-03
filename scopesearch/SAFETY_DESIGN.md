# SAFETY DESIGN

## Scope enforcement
- `scope.yml` defines allowed `domains` and `cidr` ranges.
- API validates every requested scan target before queueing.
- Worker re-validates targets before execution.

## Network safety controls
- Localhost and private/internal addresses are blocked unless explicitly included in CIDR scope.
- Scanning rate is throttled with worker sleep delay (`WORKER_RATE_LIMIT_SECONDS`).

## Capability boundaries
- ScopeSearch only performs discovery/fingerprinting/posture checks.
- No offensive exploitation modules are included.

## User-facing warnings
- Prominent UI warning: `Only scan assets you own or are authorized to test.`
