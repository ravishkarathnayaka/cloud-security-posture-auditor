"""
scanner.py - Core evaluation engine mapping cloud resources to CIS benchmark rules.
"""

from typing import List
from models import CloudResource, Finding
from rules import ALL_RULES


class CloudSecurityScanner:
    """Evaluates cloud resources against the registered CIS Benchmark rules."""

    def __init__(self, rules: List = None):
        self.rules = rules or ALL_RULES

    def scan(self, resources: List[CloudResource]) -> List[Finding]:
        """
        Executes all registered rules across all provided cloud resources.
        Returns a complete list of findings (both PASS and FAIL).
        """
        findings: List[Finding] = []

        for resource in resources:
            for rule in self.rules:
                finding = rule.evaluate(resource)
                if finding:
                    findings.append(finding)

        return findings
