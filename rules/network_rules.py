"""
rules/network_rules.py - CIS Benchmark Rules for Network Security Groups & Firewalls.
"""

from typing import Optional, List
from models import CloudResource, Finding, Severity, ResourceCategory, ComplianceStatus, CISControlMapping
from rules.base import BaseRule


class RuleRestrictedRDP(BaseRule):
    rule_id = "NET-CIS-3.1"
    title = "Network Security Groups Must Restrict Inbound RDP (Port 3389) from 0.0.0.0/0"
    description = "Exposing Remote Desktop Protocol (TCP 3389) directly to the public internet enables brute-force and ransomware infiltration."
    severity = Severity.CRITICAL
    category = ResourceCategory.NETWORK
    cis_id = "CIS 5.2.1"
    cis_title = "Ensure that RDP access is restricted from the internet"
    mitre_technique_id = "T1133"
    mitre_technique_name = "External Remote Services"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.category != ResourceCategory.NETWORK:
            return None

        rules: List[dict] = resource.properties.get("security_rules", [])
        exposed = False
        offending_rule = ""

        for r in rules:
            if (
                r.get("direction") == "Inbound"
                and r.get("access") == "Allow"
                and r.get("source_address_prefix") in ["*", "0.0.0.0/0", "Internet"]
                and (r.get("destination_port_range") in ["3389", "*"] or "3389" in str(r.get("destination_port_ranges", [])))
            ):
                exposed = True
                offending_rule = r.get("name", "UnknownRule")
                break

        status = ComplianceStatus.FAIL if exposed else ComplianceStatus.PASS
        rationale = (
            f"CRITICAL: Inbound security rule '{offending_rule}' allows unauthenticated public access to RDP (3389)."
            if exposed else
            "Inbound RDP port 3389 is restricted to private CIDRs or blocked."
        )

        guidance = "Remove public RDP rule and enforce access via Azure Bastion, AWS Systems Manager, or VPN."
        cli = f"az network nsg rule delete --resource-group <RG> --nsg-name {resource.name} --name {offending_rule or 'Allow-Any-RDP'}"

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


class RuleRestrictedSSH(BaseRule):
    rule_id = "NET-CIS-3.2"
    title = "Network Security Groups Must Restrict Inbound SSH (Port 22) from 0.0.0.0/0"
    description = "Exposing Secure Shell (TCP 22) to the global internet makes host infrastructure susceptible to automated credential attacks."
    severity = Severity.HIGH
    category = ResourceCategory.NETWORK
    cis_id = "CIS 5.2.2"
    cis_title = "Ensure that SSH access is restricted from the internet"
    mitre_technique_id = "T1133"
    mitre_technique_name = "External Remote Services"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.category != ResourceCategory.NETWORK:
            return None

        rules: List[dict] = resource.properties.get("security_rules", [])
        exposed = False
        offending_rule = ""

        for r in rules:
            if (
                r.get("direction") == "Inbound"
                and r.get("access") == "Allow"
                and r.get("source_address_prefix") in ["*", "0.0.0.0/0", "Internet"]
                and (r.get("destination_port_range") in ["22", "*"] or "22" in str(r.get("destination_port_ranges", [])))
            ):
                exposed = True
                offending_rule = r.get("name", "UnknownRule")
                break

        status = ComplianceStatus.FAIL if exposed else ComplianceStatus.PASS
        rationale = (
            f"HIGH: Inbound security rule '{offending_rule}' allows unauthenticated public access to SSH (22)."
            if exposed else
            "Inbound SSH port 22 is restricted to authorized management subnets."
        )

        guidance = "Delete public SSH rule and route access through a hardened jump host or Session Manager."
        cli = f"az network nsg rule delete --resource-group <RG> --nsg-name {resource.name} --name {offending_rule or 'Allow-Any-SSH'}"

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


class RuleRestrictedDatabasePorts(BaseRule):
    rule_id = "NET-CIS-3.3"
    title = "Database Ports (MySQL, PostgreSQL, MSSQL) Must Not Be Publicly Accessible"
    description = "Exposing database ports (3306, 5432, 1433) to the public internet enables unauthorized data queries and exfiltration."
    severity = Severity.CRITICAL
    category = ResourceCategory.NETWORK
    cis_id = "CIS 5.2.3"
    cis_title = "Ensure that database listener ports are isolated from public ingress"
    mitre_technique_id = "T1190"
    mitre_technique_name = "Exploit Public-Facing Application"

    def evaluate(self, resource: CloudResource) -> Optional[Finding]:
        if resource.category != ResourceCategory.NETWORK:
            return None

        db_ports = ["3306", "5432", "1433", "27017"]
        rules: List[dict] = resource.properties.get("security_rules", [])
        exposed = False
        offending_rule = ""
        found_port = ""

        for r in rules:
            dest_port = str(r.get("destination_port_range", ""))
            if (
                r.get("direction") == "Inbound"
                and r.get("access") == "Allow"
                and r.get("source_address_prefix") in ["*", "0.0.0.0/0", "Internet"]
                and (dest_port in db_ports or any(p in dest_port for p in db_ports))
            ):
                exposed = True
                offending_rule = r.get("name", "UnknownRule")
                found_port = dest_port
                break

        status = ComplianceStatus.FAIL if exposed else ComplianceStatus.PASS
        rationale = (
            f"CRITICAL: Inbound security rule '{offending_rule}' opens database port {found_port} to 0.0.0.0/0."
            if exposed else
            "All database ports are isolated within private virtual network boundaries."
        )

        guidance = "Isolate database tier behind private subnets and allow access strictly from application gateway tiers."
        cli = f"az network nsg rule delete --resource-group <RG> --nsg-name {resource.name} --name {offending_rule or 'Allow-Database-Public'}"

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
