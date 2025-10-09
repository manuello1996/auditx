from __future__ import annotations

from auditx.core.facts import FactStore
from auditx.core.models import CheckMeta, CheckResult, RunContext, Severity, Status
from auditx.core.runner import run_all


def _make_check(idx: int):
    class SampleCheck:
        meta = CheckMeta(
            id=f"test.check.{idx}",
            name=f"Check {idx}",
            version="1.0.0",
            tech="zabbix",
            severity=Severity.INFO,
            tags=set(),
            description="",
        )

        def run(self, ctx: RunContext) -> CheckResult:  # pragma: nocover - trivial invocation
            return CheckResult(
                meta=self.meta,
                status=Status.PASS,
                summary=f"Check {idx} completed",
            )

    return SampleCheck


def test_run_all_reports_progress_sequential() -> None:
    check_classes = [_make_check(i) for i in range(1, 4)]
    ctx = RunContext(tech_filter=set(), config={}, env={}, facts=FactStore())
    progress_calls: list[tuple[int, int]] = []

    def record_progress(done: int, total: int) -> None:
        progress_calls.append((done, total))

    results = run_all(check_classes, ctx, parallel=False, on_progress=record_progress)

    assert [res.meta.id for res in results] == [cls.meta.id for cls in check_classes]
    assert progress_calls == [(1, 3), (2, 3), (3, 3)]
