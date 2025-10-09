from __future__ import annotations
import pkgutil
from importlib import import_module
from importlib.metadata import entry_points

def load_all_providers() -> None:
    """Import all modules under auditx.providers and all entry-point providers.

    Providers must call register_provider(tech, fn) at import time.
    """
    # 1) Local package scan
    try:
        import auditx.providers as root
        for _, name, _ in pkgutil.walk_packages(root.__path__, root.__name__ + "."):
            import_module(name)
    except Exception:
        pass

    # 2) Plugins via entry points (group: auditx.providers)
    try:
        for ep in entry_points(group="auditx.providers"):
            import_module(ep.module)
    except Exception:
        pass
