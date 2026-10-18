"""
models.py - Data schemas and types for the Cloud Security Posture Management (CSPM) Auditor.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class CloudProvider(str, Enum):
    AZURE = "AZURE"
    AWS = "AWS"


class ResourceCategory(str, Enum):
    IDENTITY = "IDENTITY"
    STORAGE = "STORAGE"
    NETWORK = "NETWORK"
    COMPUTE = "COMPUTE"
    LOGGING = "LOGGING"


class ComplianceStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass
class CloudResource:
    """Represents an audited cloud asset (VM, S3 bucket, Blob container, NSG, IAM user)."""
    resource_id: str
    name: str
    provider: CloudProvider
    category: ResourceCategory
    resource_type: str
    region: str
    properties: Dict[str, Any]
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class CISControlMapping:
    """Mapping to Center for Internet Security (CIS) Benchmark controls and MITRE ATT&CK."""
    cis_id: str
    cis_title: str
    cis_benchmark_version: str
    mitre_technique_id: str
    mitre_technique_name: str


@dataclass
class Finding:
    """A detected security misconfiguration or compliance failure."""
    finding_id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: ResourceCategory
    provider: CloudProvider
    resource_id: str
    resource_name: str
    cis_mapping: CISControlMapping
    status: ComplianceStatus
    rationale: str
    remediation_guidance: str
    remediation_cli: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


@dataclass
class CategoryScore:
    """Aggregated compliance score for a security domain (e.g., Storage, Network)."""
    category: ResourceCategory
    total_checks: int
    passed_checks: int
    failed_checks: int
    score_percentage: float


@dataclass
class PostureSummary:
    """Executive summary metrics for an entire cloud tenant audit."""
    timestamp: str
    total_resources_scanned: int
    total_rules_evaluated: int
    total_passed: int
    total_failed: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    composite_posture_score: float
    posture_grade: str
    category_scores: Dict[str, CategoryScore]
    findings: List[Finding]
