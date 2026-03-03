import ipaddress
from functools import lru_cache
from pathlib import Path

import yaml

from scopesearch.core.config import settings


class ScopeError(ValueError):
    pass


class ScopeValidator:
    def __init__(self, domains: list[str], cidr: list[str]):
        self.domains = [d.lower().strip() for d in domains]
        self.networks = [ipaddress.ip_network(c, strict=False) for c in cidr]

    def is_ip_allowed(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self.networks)

    def is_domain_allowed(self, domain: str) -> bool:
        d = domain.lower().strip().rstrip(".")
        return any(d == root or d.endswith(f".{root}") for root in self.domains)

    def ensure_target_allowed(self, target: str) -> None:
        target = target.strip()
        try:
            ip = ipaddress.ip_address(target)
            if ip.is_loopback or ip.is_link_local or ip.is_private:
                if not self.is_ip_allowed(target):
                    raise ScopeError(f"Target {target} is internal/loopback and not explicitly allowed")
            elif not self.is_ip_allowed(target):
                raise ScopeError(f"Target {target} is outside configured cidr scope")
            return
        except ValueError:
            pass

        if target in {"localhost", "127.0.0.1"}:
            raise ScopeError("Localhost scans are blocked unless explicitly configured as CIDR range")
        if not self.is_domain_allowed(target):
            raise ScopeError(f"Target {target} is outside configured domain scope")


@lru_cache(maxsize=1)
def load_scope() -> ScopeValidator:
    path = Path(settings.scope_file)
    if not path.exists():
        raise ScopeError(f"scope file not found: {path}")
    data = yaml.safe_load(path.read_text()) or {}
    return ScopeValidator(domains=data.get("domains", []), cidr=data.get("cidr", []))
