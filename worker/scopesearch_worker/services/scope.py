import ipaddress
from functools import lru_cache
from pathlib import Path

import yaml

from scopesearch_worker.core.config import settings


class ScopeError(ValueError):
    pass


class ScopeValidator:
    def __init__(self, domains: list[str], cidr: list[str]):
        self.domains = [d.lower().strip() for d in domains]
        self.networks = [ipaddress.ip_network(c, strict=False) for c in cidr]

    def ensure_target_allowed(self, target: str) -> None:
        target = target.strip()
        try:
            ip = ipaddress.ip_address(target)
            if not any(ip in n for n in self.networks):
                raise ScopeError(f"{target} outside CIDR scope")
            return
        except ValueError:
            pass
        d = target.lower().rstrip(".")
        if not any(d == root or d.endswith(f".{root}") for root in self.domains):
            raise ScopeError(f"{target} outside domain scope")


@lru_cache(maxsize=1)
def load_scope() -> ScopeValidator:
    data = yaml.safe_load(Path(settings.scope_file).read_text()) or {}
    return ScopeValidator(domains=data.get("domains", []), cidr=data.get("cidr", []))
