from __future__ import annotations
from abc import ABC, abstractmethod
from .models import CheckMeta, CheckResult, RunContext


class BaseCheck(ABC):
    """Base class for all audit checks.
    
    Each check must define a 'meta' class attribute with CheckMeta
    and implement the 'run' method that executes the check logic.
    """
    meta: CheckMeta

    @abstractmethod
    def run(self, ctx: RunContext) -> CheckResult:
        """Execute the check and return results.
        
        Args:
            ctx: Runtime context with configuration, environment, and facts
            
        Returns:
            CheckResult with status, summary, and optional details
        """
        ...
