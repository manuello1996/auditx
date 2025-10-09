from __future__ import annotations
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Callable, Sequence
from .models import CheckResult, RunContext, Status, CheckMeta, Severity

# Default worker count: 0 means use os.cpu_count()
_DEFAULT_WORKERS = 0


def _run_one(check_cls: type, ctx: RunContext) -> CheckResult:
    """Execute a single check and return its result.
    
    Instantiates the check class, runs it, and measures execution time.
    Catches and converts exceptions to ERROR results.
    
    Args:
        check_cls: Check class to instantiate and run
        ctx: Runtime context with configuration and facts
        
    Returns:
        CheckResult with status, summary, and timing information
    """
    check = check_cls()
    start_time = time.perf_counter()
    try:
        result = check.run(ctx)
        result.duration_ms = int((time.perf_counter() - start_time) * 1000)
        return result
    except Exception as e:
        # Create a basic metadata object if the check doesn't have one
        meta = getattr(check, "meta", None) or CheckMeta(
            id=f"{check_cls.__module__}.{check_cls.__name__}",
            name=check_cls.__name__,
            version="0",
            tech="linux",
            severity=Severity.INFO
        )
        return CheckResult(meta=meta, status=Status.ERROR, summary=str(e))

def run_all(
    check_classes: Sequence[type],
    ctx: RunContext,
    parallel: bool = True,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[CheckResult]:
    """Execute all checks sequentially or in parallel.
    
    Args:
        check_classes: Sequence of check classes to execute
        ctx: Runtime context with configuration and facts
        parallel: If True, run checks in parallel using ProcessPoolExecutor
        on_progress: Optional callback(completed, total) for progress updates
        
    Returns:
        List of CheckResult objects, one per check
    """
    total = len(check_classes)
    if not parallel:
        # Sequential execution
        results: list[CheckResult] = []
        for index, check_class in enumerate(check_classes, start=1):
            result = _run_one(check_class, ctx)
            results.append(result)
            if on_progress:
                on_progress(index, total)
        return results
    
    # Parallel execution using process pool
    results_parallel: list[CheckResult] = []
    with ProcessPoolExecutor(max_workers=_DEFAULT_WORKERS or None) as executor:
        futures = {executor.submit(_run_one, check_cls, ctx): check_cls for check_cls in check_classes}
        completed = 0
        for future in as_completed(futures):
            results_parallel.append(future.result())
            completed += 1
            if on_progress:
                on_progress(completed, total)
    return results_parallel
