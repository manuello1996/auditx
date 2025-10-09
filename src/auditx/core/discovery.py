from __future__ import annotations
import pkgutil
from importlib import import_module
from importlib.metadata import entry_points
from typing import Iterator
from .base import BaseCheck


def iter_local_checks() -> Iterator[type[BaseCheck]]:
    """Discover and yield all check classes from the local auditx.checks package.
    
    Walks the auditx.checks package tree looking for modules ending in '_check',
    then yields all BaseCheck subclasses found in those modules.
    
    Yields:
        Check class objects (not instances)
    """
    import auditx.checks as root
    for _, name, _ in pkgutil.walk_packages(root.__path__, root.__name__ + "."):
        if name.endswith("_check"):
            mod = import_module(name)
            for attr in getattr(mod, "__all__", dir(mod)):
                obj = getattr(mod, attr)
                if isinstance(obj, type) and issubclass(obj, BaseCheck) and obj is not BaseCheck:
                    yield obj


def iter_entrypoint_checks() -> Iterator[type[BaseCheck]]:
    """Discover and yield check classes from external plugins.
    
    Uses the 'auditx.checks' entry point group to find externally
    registered check modules.
    
    Yields:
        Check class objects from plugins
    """
    for ep in entry_points(group="auditx.checks"):
        mod = import_module(ep.module)
        for attr in getattr(mod, "__all__", dir(mod)):
            obj = getattr(mod, attr)
            if isinstance(obj, type) and issubclass(obj, BaseCheck) and obj is not BaseCheck:
                yield obj
