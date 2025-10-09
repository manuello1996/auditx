from __future__ import annotations
"""Provider for ${tech} base facts.

Registers at import time via register_provider("${tech}", provider_fn).
"""
from typing import Dict
from auditx.core.facts import register_provider

def ${fn_name}(params: Dict) -> Dict:
    """Collect basic ${tech} facts.

    Args:
        params: Configuration dictionary for ${tech}.
    Returns:
        Mapping of fact keys to values.
    """
    # TODO: add real data collection
    return {
        "${tech}.example": "value"
    }

register_provider("${tech}", ${fn_name})
