from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Dict, Set, TypedDict


class Severity(str, Enum):
    """Severity levels for checks."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Status(str, Enum):
    """Status values for check results."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    ERROR = "ERROR"


# TODO: Make this fully extensible via plugin system
Tech = Literal["linux", "zabbix", "mysql"]


class InputSpec(TypedDict, total=False):
    """Specification for a check input parameter."""
    key: str
    required: bool
    secret: bool
    description: str

@dataclass(frozen=True)
class CheckMeta:
    """Metadata describing a check.
    
    Attributes:
        id: Unique check identifier (e.g., 'linux.hostname.sanity')
        name: Human-readable check name
        version: Check version string
        tech: Technology this check applies to
        severity: Severity level if the check fails
        tags: Set of tags for categorization
        description: Brief description of what the check verifies
        requires_privileges: Whether check needs elevated permissions
        inputs: Tuple of required/optional input specifications
        required_facts: Tuple of fact keys this check depends on
        remediation: Default remediation advice
        explanation: Default explanation of why this check matters
    """
    id: str
    name: str
    version: str
    tech: Tech
    severity: Severity
    tags: Set[str] = field(default_factory=set)
    description: str = ""
    requires_privileges: bool = False
    inputs: tuple[InputSpec, ...] = ()
    required_facts: tuple[str, ...] = ()
    remediation: str | None = None
    explanation: str | None = None

@dataclass
class RunContext:
    """Runtime context passed to checks during execution.
    
    Attributes:
        tech_filter: Set of technologies to run checks for
        config: Configuration dictionary
        env: Environment variables dictionary
        facts: FactStore with collected facts from providers
    """
    tech_filter: set[str]
    config: Dict[str, Any]
    env: Dict[str, str]
    facts: "FactStore"


@dataclass
class CheckResult:
    """Result of executing a check.
    
    Attributes:
        meta: Check metadata
        status: Execution status (PASS, FAIL, WARN, SKIP, ERROR)
        summary: One-line summary of the result
        details: Dictionary with detailed findings
        remediation: Advice on how to fix issues (defaults to meta.remediation)
        explanation: Explanation of why this check matters (defaults to meta.explanation)
        duration_ms: Execution time in milliseconds
    """
    meta: CheckMeta
    status: Status
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None
    explanation: str | None = None
    duration_ms: int = 0

    def __post_init__(self) -> None:
        """Initialize remediation and explanation from meta if not provided."""
        if self.remediation is None and self.meta.remediation:
            self.remediation = self.meta.remediation
        if self.explanation is None and self.meta.explanation:
            self.explanation = self.meta.explanation
