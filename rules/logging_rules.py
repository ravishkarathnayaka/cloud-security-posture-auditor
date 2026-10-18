"""
rules/logging_rules.py - CIS Benchmark Rules for Audit Logging & Forensics.
"""

from typing import Optional
from models import CloudResource, Finding, Severity, ResourceCategory, ComplianceStatus, CISControlMapping
from rules.base import BaseRule


class RuleAuditLoggingEnabled(BaseRule):
    rule_id = "LOG-CIS-5.1"
    title = "Central Cloud Audit Logging Must Be Enabled with Minimum 90-Day Retention"
    description = "Without immutable central audit logging (CloudTrail / Azure Activity Log), security incidents cannot be forensically investigated."
    severity = Severity.CRITICAL
    category = ResourceCategory.LOGGING
    cis_id = "CIS 3.1"
    cis_title = "Ensure a log profile exists and captures all activity log categories with >= 90 days retention"
    mitre_technique_id = "T1562.008"
    mitre_technique_name = "Impair Defenses: Disable Cloud Logs"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.category != ResourceCategory.LOGGING:
            return None

        is_enabled = resource.properties.get("activity_log_enabled", False)
        retention = resource.properties.get("retention_policy", {}).get("days", 0)
        compliant = is_enabled and retention >= 90

        status = ComplianceStatus.PASS if compliant else ComplianceStatus.FAIL
        rationale = (
            f"Central audit logging is enabled with {retention} days forensic retention."
            if compliant else
            "CRITICAL: Central cloud activity logging is disabled or has insufficient retention (< 90 days)."
        )

        guidance = "Create an Azure Log Profile or AWS CloudTrail multi-region trail configured with S3 and CloudWatch delivery."
        cli = "az monitor log-profiles create --name default --categories Write Delete Action --locations global eastus --days 365 --enabled true"

        return Finding(
            finding_id=f"{self.rule_id}-{resource.name}",
            rule_id=self.rule_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            category=self.category,
            provider=resource.provider,
            resource_id=resource.resource_id,
            resource_name=resource.name,
            cis_mapping=CISControlMapping(
                cis_id=self.cis_id,
                cis_title=self.cis_title,
                cis_benchmark_version=self.cis_version,
                mitre_technique_id=self.mitre_technique_id,
                mitre_technique_name=self.mitre_technique_name
            ),
            status=status,
            rationale=rationale,
            remediation_guidance=guidance,
            remediation_cli=cli
        )
