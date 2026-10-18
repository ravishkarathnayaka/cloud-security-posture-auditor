"""
rules/storage_rules.py - CIS Benchmark Rules for Cloud Storage (Azure Blob & AWS S3).
"""

from typing import Optional
from models import CloudResource, Finding, Severity, ResourceCategory, ComplianceStatus, CISControlMapping, CloudProvider
from rules.base import BaseRule


class RuleStoragePublicAccess(BaseRule):
    rule_id = "STORAGE-CIS-2.1"
    title = "Cloud Storage Buckets & Containers Must Block Public Anonymous Read Access"
    description = "Publicly readable object storage is a primary cause of enterprise data leaks and regulatory non-compliance."
    severity = Severity.CRITICAL
    category = ResourceCategory.STORAGE
    cis_id = "CIS 2.1.5"
    cis_title = "Ensure that Cloud Storage is not publicly accessible"
    mitre_technique_id = "T1530"
    mitre_technique_name = "Data from Cloud Storage Object"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.category != ResourceCategory.STORAGE:
            return None

        is_public = False
        if resource.provider == CloudProvider.AZURE:
            is_public = resource.properties.get("allow_blob_public_access", False)
            cli = f"az storage account update --name {resource.name} --allow-blob-public-access false"
        else:
            pab = resource.properties.get("public_access_block", {})
            is_public = not (pab.get("block_public_acls") and pab.get("block_public_policy"))
            cli = f"aws s3api put-public-access-block --bucket {resource.name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

        status = ComplianceStatus.FAIL if is_public else ComplianceStatus.PASS
        rationale = (
            "CRITICAL: Storage account / bucket allows anonymous internet users to read or download objects."
            if is_public else
            "Public access block is actively enforced. Anonymous access is strictly prohibited."
        )

        guidance = "Enforce Public Access Block and disable container-level anonymous access permissions."

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


class RuleStorageEncryption(BaseRule):
    rule_id = "STORAGE-CIS-2.2"
    title = "Storage at Rest Must Enforce Server-Side Encryption (SSE)"
    description = "Unencrypted data storage risks cleartext exfiltration if underlying storage media is exposed or compromised."
    severity = Severity.HIGH
    category = ResourceCategory.STORAGE
    cis_id = "CIS 2.1.1"
    cis_title = "Ensure that all Cloud Storage accounts enforce Server-Side Encryption"
    mitre_technique_id = "T1005"
    mitre_technique_name = "Data from Local System"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.category != ResourceCategory.STORAGE:
            return None

        encrypted = True
        if resource.provider == CloudProvider.AWS:
            sse = resource.properties.get("server_side_encryption", {})
            encrypted = sse.get("enabled", False)
            cli = f"aws s3api put-bucket-encryption --bucket {resource.name} --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'"
        else:
            encrypted = resource.properties.get("encryption_enabled", True)
            cli = f"az storage account update --name {resource.name} --encryption-services blob"

        status = ComplianceStatus.PASS if encrypted else ComplianceStatus.FAIL
        rationale = (
            "Server-side encryption is active and protecting object data at rest."
            if encrypted else
            "HIGH: Storage bucket does not have default server-side encryption enabled."
        )

        guidance = "Enable default AWS SSE-S3 / SSE-KMS or Azure Storage Service Encryption."

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


class RuleStorageEnforceHTTPS(BaseRule):
    rule_id = "STORAGE-CIS-2.3"
    title = "Storage Must Enforce Secure Transfer (HTTPS/TLS Only)"
    description = "Allowing unencrypted HTTP transport allows adversary Man-in-the-Middle (MitM) eavesdropping and credential theft."
    severity = Severity.MEDIUM
    category = ResourceCategory.STORAGE
    cis_id = "CIS 2.1.2"
    cis_title = "Ensure that 'Secure transfer required' is enabled for Cloud Storage"
    mitre_technique_id = "T1040"
    mitre_technique_name = "Network Sniffing"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.category != ResourceCategory.STORAGE:
            return None

        if resource.provider == CloudProvider.AZURE:
            enforce_https = resource.properties.get("supports_https_traffic_only", True)
            cli = f"az storage account update --name {resource.name} --https-only true"
        else:
            enforce_https = resource.properties.get("enforce_ssl_requests", True)
            cli = f"aws s3api put-bucket-policy --bucket {resource.name} --policy <ENFORCE_TLS_POLICY_JSON>"

        status = ComplianceStatus.PASS if enforce_https else ComplianceStatus.FAIL
        rationale = (
            "Secure transfer (HTTPS/TLS) is strictly enforced for all API and data endpoints."
            if enforce_https else
            "MEDIUM: Unencrypted plain HTTP requests are accepted by this storage account."
        )

        guidance = "Enable 'Secure transfer required' or attach an S3 bucket policy denying aws:SecureTransport: false."

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
