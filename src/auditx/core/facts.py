from __future__ import annotations
from dataclasses import dataclass, field
from inspect import Parameter, Signature, signature
from typing import Any, Callable, Dict
import json
import time
from pathlib import Path

FactKey = str  # e.g. "linux.uname"
ProgressReporter = Callable[[str], None]
ProviderCallable = Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class _ProviderEntry:
    fn: ProviderCallable
    accepts_progress: bool


def _detect_progress_support(fn: ProviderCallable) -> bool:
    """Detect if a provider function accepts a 'progress' parameter.
    
    Inspects the function signature to determine if it accepts a 'progress'
    callback parameter, allowing for progress reporting during fact collection.
    
    Args:
        fn: Provider function to inspect
        
    Returns:
        True if the function accepts a 'progress' parameter
    """
    try:
        sig: Signature = signature(fn)
    except (TypeError, ValueError):
        return False

    params = list(sig.parameters.values())
    if not params:
        return False

    # Check parameters after the first (which should be 'params')
    for param in params[1:]:
        if param.name != "progress":
            continue
        if param.kind in (Parameter.POSITIONAL_OR_KEYWORD, Parameter.KEYWORD_ONLY):
            return True
    return False

@dataclass
class FactStore:
    data: Dict[str, Dict[FactKey, Any]] = field(default_factory=dict)  # tech -> facts
    ttl: int | None = None
    persisted_path: Path | None = None
    _ts: Dict[str, float] = field(default_factory=dict)

    def get(self, key: FactKey, *, tech: str | None = None) -> Any:
        if tech:
            return (self.data.get(tech) or {}).get(key)
        for facts in self.data.values():
            if key in facts:
                return facts[key]
        return None

    def set_namespace(self, tech: str, facts: dict) -> None:
        self.data[tech] = {**(self.data.get(tech) or {}), **facts}
        self._ts[tech] = time.time()

    def is_valid(self, tech: str) -> bool:
        if self.ttl is None:
            return True
        ts = self._ts.get(tech)
        return bool(ts and (time.time() - ts) <= self.ttl)

    def save(self):
        if not self.persisted_path:
            return
        self.persisted_path.write_text(json.dumps(self.data, indent=2, default=str))

    def load(self):
        if not (self.persisted_path and self.persisted_path.exists()):
            return
        self.data = json.loads(self.persisted_path.read_text())
        now = time.time()
        self._ts = {k: now for k in self.data.keys()}

# Registry of providers per tech
_PROVIDERS: Dict[str, list[_ProviderEntry]] = {}

def register_provider(tech: str, provider: ProviderCallable) -> None:
    """Register a provider function for a specific technology.
    
    Providers are called during fact collection to gather information
    about the specified technology.
    
    Args:
        tech: Technology name (e.g., 'linux', 'mysql', 'zabbix')
        provider: Callable that returns a dictionary of facts
    """
    entry = _ProviderEntry(fn=provider, accepts_progress=_detect_progress_support(provider))
    _PROVIDERS.setdefault(tech, []).append(entry)


def registered_techs() -> set[str]:
    """Return the set of technologies with at least one registered provider."""

    return set(_PROVIDERS.keys())

def collect_facts(
    tech: str,
    params: dict,
    store: FactStore,
    *,
    reporter: ProgressReporter | None = None,
) -> None:
    """Collect facts for a technology by calling all registered providers.
    
    If facts are already cached and still valid (based on TTL), skips collection.
    Otherwise, calls all registered providers for the technology and stores results.
    
    Args:
        tech: Technology name to collect facts for
        params: Configuration parameters to pass to providers
        store: FactStore to save collected facts into
        reporter: Optional progress callback function
    """
    # Skip if we already have valid cached facts
    if tech in store.data and store.is_valid(tech):
        return
    facts: dict = {}
    for entry in _PROVIDERS.get(tech, []):
        try:
            if entry.accepts_progress:
                payload = entry.fn(params, progress=reporter)
            else:
                payload = entry.fn(params)
            facts.update(payload or {})
        except Exception as e:
            # Store provider errors as facts for debugging
            facts[f"{tech}.provider_error"] = str(e)
    store.set_namespace(tech, facts)
