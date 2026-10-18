"""
rules/__init__.py - Rule registry exporting all CIS Benchmark rule evaluators.
"""

from rules.iam_rules import RuleRootAccountMFA, RuleIAMNoWildcardAdmin, RuleCredentialRotation
from rules.storage_rules import RuleStoragePublicAccess, RuleStorageEncryption, RuleStorageEnforceHTTPS
from rules.network_rules import RuleRestrictedRDP, RuleRestrictedSSH, RuleRestrictedDatabasePorts
from rules.compute_rules import RuleVMDiskEncryption, RuleVMNoDirectPublicIP
from rules.logging_rules import RuleAuditLoggingEnabled

ALL_RULES = [
    # Identity & Access Management (CIS Section 1)
    RuleRootAccountMFA(),
    RuleIAMNoWildcardAdmin(),
    RuleCredentialRotation(),

    # Cloud Storage (CIS Section 2)
    RuleStoragePublicAccess(),
    RuleStorageEncryption(),
    RuleStorageEnforceHTTPS(),

    # Network Security Groups & Firewalls (CIS Section 3 / 5)
    RuleRestrictedRDP(),
    RuleRestrictedSSH(),
    RuleRestrictedDatabasePorts(),

    # Compute & Virtual Machines (CIS Section 7)
    RuleVMDiskEncryption(),
    RuleVMNoDirectPublicIP(),

    # Audit Logging & Monitoring (CIS Section 3)
    RuleAuditLoggingEnabled()
]
