"""
rules/iam_rules.py - CIS Benchmark Rules for Identity & Access Management (IAM).
"""

from typing import Optional
from models import CloudResource, Finding, Severity, ResourceCategory, ComplianceStatus, CISControlMapping
from rules.base import BaseRule


class RuleRootAccountMFA(BaseRule):
    rule_id = "IAM-CIS-1.1"
    title = "Root Account Must Have Multi-Factor Authentication (MFA) Enabled"
    description = "The root account represents unrestricted administrative control. MFA must be enforced to prevent account takeover."
    severity = Severity.CRITICAL
    category = ResourceCategory.IDENTITY
    cis_id = "CIS 1.1"
    cis_title = "Ensure MFA is enabled for the 'root' user account"
    mitre_technique_id = "T1078.004"
    mitre_technique_name = "Valid Accounts: Cloud Accounts"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != "iam_root_account":
            return None

        mfa_active = resource.properties.get("mfa_active", False)
        status = ComplianceStatus.PASS if mfa_active else ComplianceStatus.FAIL

        rationale = (
            "Root account has hardware or virtual MFA device configured."
            if mfa_active else
            "CRITICAL: The root account is active without Multi-Factor Authentication (MFA)."
        )

        guidance = "Log into AWS console as root, navigate to IAM > Security Credentials, and enable hardware MFA."
        cli = "aws iam enable-mfa-device --user-name root --serial-number <MFA_SERIAL>"

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


class RuleIAMNoWildcardAdmin(BaseRule):
    rule_id = "IAM-CIS-1.2"
    title = "IAM Policies Must Not Grant Wildcard Full Administrative Privileges"
    description = "IAM policies granting Action='*' and Resource='*' violate the principle of least privilege."
    severity = Severity.HIGH
    category = ResourceCategory.IDENTITY
    cis_id = "CIS 1.16"
    cis_title = "Ensure IAM policies that allow full '*:*' administrative privileges are not created"
    mitre_technique_id = "T1098"
    mitre_technique_name = "Account Manipulation"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type not in ["iam_role", "iam_policy", "iam_user"]:
            return None

        policies = resource.properties.get("policies", [])
        has_wildcard = False
        for pol in policies:
            for stmt in pol.get("statements", []):
                if stmt.get("effect") == "Allow" and stmt.get("action") == "*" and stmt.get("resource") == "*":
                    has_wildcard = True
                    break

        status = ComplianceStatus.FAIL if has_wildcard else ComplianceStatus.PASS
        rationale = (
            "HIGH: Role has inline/attached policies granting full '*:*' wildcard administrative control."
            if has_wildcard else
            "All attached policies adhere to granular resource and action scoping."
        )

        guidance = "Replace wildcard '*' actions with granular service permissions (e.g. s3:PutObject, ec2:DescribeInstances)."
        cli = f"aws iam delete-role-policy --role-name {resource.name} --policy-name OverlyPermissiveAdminAccess"

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


class RuleCredentialRotation(BaseRule):
    rule_id = "IAM-CIS-1.3"
    title = "User Access Keys Must Be Rotated Every 90 Days or Less"
    description = "Long-lived credentials significantly increase exposure window in the event of credential leakage or exposure."
    severity = Severity.MEDIUM
    category = ResourceCategory.IDENTITY
    cis_id = "CIS 1.4"
    cis_title = "Ensure access keys are rotated every 90 days or less"
    mitre_technique_id = "T1078.004"
    mitre_technique_name = "Valid Accounts: Cloud Accounts"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.resource_type != "iam_user":
            return None

        age_days = resource.properties.get("access_key_age_days", 0)
        is_expired = age_days > 90
        status = ComplianceStatus.FAIL if is_expired else ComplianceStatus.PASS

        rationale = (
            f"MEDIUM: Access key has been active for {age_days} days without rotation (exceeds 90-day threshold)."
            if is_expired else
            f"Access key age is {age_days} days (within compliant 90-day lifecycle)."
        )

        guidance = "Generate a new access key, deploy to workload secrets, test connectivity, and deactivate the old key."
        cli = f"aws iam update-access-key --user-name {resource.name} --access-key-id <KEY_ID> --status Inactive"

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
