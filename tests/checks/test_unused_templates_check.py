from auditx.checks.zabbix.unused_templates_check import UnusedTemplatesCheck
from auditx.core.models import RunContext, Status


class MockFacts:
    def __init__(self, data=None):
        # Structure: {tech: {fact_key: value}}
        # Convert flat keys like "zabbix.templates" into nested structure
        self.data = {}
        if data:
            for key, value in data.items():
                if '.' in key:
                    tech, fact_key = key.split('.', 1)
                    if tech not in self.data:
                        self.data[tech] = {}
                    self.data[tech][key] = value
                else:
                    self.data[key] = value

    def get(self, key, tech=None):
        if tech:
            tech_facts = self.data.get(tech) or {}
            return tech_facts.get(key)
        # Search all tech namespaces for the key
        for facts in self.data.values():
            if isinstance(facts, dict) and key in facts:
                return facts[key]
        return None


def test_unused_templates_runs():
    """Test that the check runs without errors."""
    facts = MockFacts()
    ctx = RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=facts)
    res = UnusedTemplatesCheck().run(ctx)
    assert res.status in {Status.PASS, Status.WARN, Status.FAIL, Status.SKIP, Status.ERROR}
    assert isinstance(res.summary, str) and len(res.summary) > 0


def test_unused_templates_no_templates():
    """Test behavior when no templates are found."""
    facts = MockFacts({
        "zabbix.templates": [],
        "zabbix.hosts": []
    })
    ctx = RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=facts)
    res = UnusedTemplatesCheck().run(ctx)
    assert res.status == Status.SKIP
    assert "No templates found" in res.summary


def test_unused_templates_all_used():
    """Test when all templates are used by hosts."""
    facts = MockFacts({
        "zabbix.templates": [
            {"id": "1", "name": "Template 1", "description": "Desc 1"},
            {"id": "2", "name": "Template 2", "description": "Desc 2"}
        ],
        "zabbix.hosts": [
            {"id": "100", "name": "Host 1", "template_ids": ["1", "2"]},
            {"id": "101", "name": "Host 2", "template_ids": ["1"]}
        ]
    })
    ctx = RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=facts)
    res = UnusedTemplatesCheck().run(ctx)
    assert res.status == Status.PASS
    assert "All 2 template(s) are in use" in res.summary
    assert res.details["unused_templates"] == 0


def test_unused_templates_some_unused():
    """Test when some templates are unused."""
    facts = MockFacts({
        "zabbix.templates": [
            {"id": "1", "name": "Used Template", "description": "This one is used"},
            {"id": "2", "name": "Unused Template A", "description": "Not used"},
            {"id": "3", "name": "Unused Template B", "description": "Also not used"}
        ],
        "zabbix.hosts": [
            {"id": "100", "name": "Host 1", "template_ids": ["1"]},
            {"id": "101", "name": "Host 2", "template_ids": []}
        ]
    })
    ctx = RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=facts)
    res = UnusedTemplatesCheck().run(ctx)
    assert res.status == Status.WARN
    assert "2 unused template(s) found" in res.summary
    assert "Unused Template A, Unused Template B" in res.summary
    assert res.details["unused_templates"] == 2
    assert res.details["used_templates"] == 1
    assert len(res.details["unused_template_list"]) == 2


def test_unused_templates_many_unused_truncated():
    """Test that many unused templates get truncated in summary."""
    templates = [{"id": str(i), "name": f"Template {i}", "description": f"Desc {i}"} for i in range(10)]
    
    facts = MockFacts({
        "zabbix.templates": templates,
        "zabbix.hosts": [
            {"id": "100", "name": "Host 1", "template_ids": ["0"]}  # Only first template used
        ]
    })
    ctx = RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=facts)
    res = UnusedTemplatesCheck().run(ctx)
    assert res.status == Status.WARN
    assert "9 unused template(s) found" in res.summary
    assert "(and 4 more)" in res.summary  # Should truncate after 5
    assert res.details["unused_templates"] == 9


def test_unused_templates_invalid_template_data():
    """Test error handling for invalid template data."""
    facts = MockFacts({
        "zabbix.templates": "invalid",  # Not a list
        "zabbix.hosts": []
    })
    ctx = RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=facts)
    res = UnusedTemplatesCheck().run(ctx)
    assert res.status == Status.ERROR
    assert "Invalid template data format" in res.summary


def test_unused_templates_invalid_host_data():
    """Test error handling for invalid host data."""
    facts = MockFacts({
        "zabbix.templates": [],
        "zabbix.hosts": "invalid"  # Not a list
    })
    ctx = RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=facts)
    res = UnusedTemplatesCheck().run(ctx)
    assert res.status == Status.ERROR
    assert "Invalid host data format" in res.summary


def test_unused_templates_missing_template_ids():
    """Test handling of hosts without template_ids field."""
    facts = MockFacts({
        "zabbix.templates": [
            {"id": "1", "name": "Template 1", "description": "Desc 1"}
        ],
        "zabbix.hosts": [
            {"id": "100", "name": "Host 1"},  # No template_ids field
            {"id": "101", "name": "Host 2", "template_ids": None}  # Null template_ids
        ]
    })
    ctx = RunContext(tech_filter={"zabbix"}, config={}, env={}, facts=facts)
    res = UnusedTemplatesCheck().run(ctx)
    assert res.status == Status.WARN
    assert "1 unused template(s) found" in res.summary
