"""
rules/base.py - Base rule interface for all CIS Benchmark security checks.
"""

from abc import ABC, abstractmethod
from typing import Optional
from models import CloudResource, Finding, ComplianceStatus


class BaseRule(ABC):
    """Abstract Base Class for CIS Benchmark checks."""
    rule_id: str
    title: str
    description: str
    severity: str
    category: str
    cis_id: str
    cis_title: str
    cis_version: str = "v3.0.0"
    mitre_technique_id: str
    mitre_technique_name: str

    @abstractmethod
    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        """
        Evaluates a cloud resource against this rule.
        Returns a Finding if compliant/non-compliant, or None if rule is not applicable.
        """
        pass
