"""
rules/compute_rules.py - CIS Benchmark Rules for Compute & Virtual Machines.
"""

from typing import Optional
from models import CloudResource, Finding, Severity, ResourceCategory, ComplianceStatus, CISControlMapping
from rules.base import BaseRule


class RuleVMDiskEncryption(BaseRule):
    rule_id = "COMPUTE-CIS-4.1"
    title = "Virtual Machine OS and Data Disks Must Be Encrypted at Rest"
    description = "Unencrypted virtual machine disks expose underlying filesystem telemetry and stored credentials to physical snapshot theft."
    severity = Severity.HIGH
    category = ResourceCategory.COMPUTE
    cis_id = "CIS 7.1"
    cis_title = "Ensure that OS and Data Disks are encrypted with Customer Managed Keys or Platform Keys"
    mitre_technique_id = "T1005"
    mitre_technique_name = "Data from Local System"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.category != ResourceCategory.COMPUTE or resource.resource_type != "virtual_machine":
            return None

        os_disk = resource.properties.get("os_disk", {})
        enc_type = os_disk.get("encryption_type", "Unencrypted")
        is_encrypted = enc_type != "Unencrypted"

        status = ComplianceStatus.PASS if is_encrypted else ComplianceStatus.FAIL
        rationale = (
            f"OS disk is encrypted using '{enc_type}'."
            if is_encrypted else
            "HIGH: Virtual Machine OS disk is unencrypted at rest."
        )

        guidance = "Enable Azure Disk Encryption (ADE) or attach Disk Encryption Sets (DES) using Azure Key Vault."
        cli = f"az vm encryption enable --resource-group <RG> --name {resource.name} --disk-encryption-keyvault <VAULT_NAME>"

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


class RuleVMNoDirectPublicIP(BaseRule):
    rule_id = "COMPUTE-CIS-4.2"
    title = "Virtual Machines Should Not Have Direct Public IP Addresses Attached"
    description = "Workload VMs should be shielded behind Layer 4/7 load balancers and NAT gateways rather than direct public IPs."
    severity = Severity.MEDIUM
    category = ResourceCategory.COMPUTE
    cis_id = "CIS 7.4"
    cis_title = "Ensure that Virtual Machines do not have direct public IPv4 addresses attached"
    mitre_technique_id = "T1190"
    mitre_technique_name = "Exploit Public-Facing Application"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.category != ResourceCategory.COMPUTE or resource.resource_type != "virtual_machine":
            return None

        has_public_ip = resource.properties.get("public_ip_attached", False)
        public_ip = resource.properties.get("public_ip_address", "N/A")
        status = ComplianceStatus.FAIL if has_public_ip else ComplianceStatus.PASS

        rationale = (
            f"MEDIUM: VM has direct public IP '{public_ip}' exposed to the public internet."
            if has_public_ip else
            "VM is hosted within a private subnet without direct public IP exposure."
        )

        guidance = "Disassociate the Public IP from the VM network interface and route egress traffic via a NAT Gateway."
        cli = f"az network nic ip-config update --resource-group <RG> --nic-name <NIC> --name <IP_CONFIG> --remove publicIpAddress"

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
