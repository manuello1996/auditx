from ${module_path} import ${class_name}
from auditx.core.models import RunContext, Status

class DummyFacts:
    def get(self, *args, **kwargs): return None

def test_${slug}_runs():
    ctx = RunContext(tech_filter={"${tech}"}, config={}, env={}, facts=DummyFacts())
    res = ${class_name}().run(ctx)
    assert res.status in {Status.PASS, Status.WARN, Status.FAIL, Status.SKIP, Status.ERROR}
    assert isinstance(res.summary, str) and len(res.summary) > 0
