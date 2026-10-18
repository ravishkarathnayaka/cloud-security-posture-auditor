# Automated Cloud Security Posture Management (CSPM) & CIS Benchmark Auditor

An enterprise-grade multi-cloud compliance and posture evaluation engine engineered in Python. This system automates the detection of critical cloud security misconfigurations across **Microsoft Azure** and **Amazon Web Services (AWS)** against the **Center for Internet Security (CIS) Benchmarks (v3.0.0)** and the **MITRE ATT&CK for Cloud Matrix**. It calculates an overall **Cloud Security Posture Index (CSPI)**, assigns letter grades, exports SIEM-ready JSON audit telemetry, and auto-generates executable remediation runbooks.

---

## Architecture Overview

```text
               +-----------------------------------------------------+
               |       Multi-Cloud Infrastructure Telemetry          |
               |       (Azure Subscriptions & AWS Accounts)          |
               +-----------------------------------------------------+
                                          |
                                          v
               +-----------------------------------------------------+
               |         1. Cloud Inventory Collector Engine         |
               |   (Azure Resource Manager / AWS Boto3 / CI-CD JSON) |
               +-----------------------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
        v                                                                   v
+-------------------------------+                                   +-------------------------------+
|  2. CIS Benchmark Rule Engine |                                   | 3. MITRE ATT&CK Cloud Matrix  |
| • IAM Controls (MFA / Keys)   |                                   | • T1078 Cloud Valid Accounts  |
| • Storage (Public / Crypto)   |                                   | • T1530 Cloud Object Theft    |
| • Network (RDP / SSH / DB)    |                                   | • T1190 Exploit Public App    |
| • Compute & Logging Retention |                                   | • T1562 Impair Cloud Defenses |
+-------------------------------+                                   +-------------------------------+
        |                                                                   |
        +---------------------------------+---------------------------------+
                                          |
                                          v
               +-----------------------------------------------------+
               |         4. Risk Scoring & Compliance Matrix         |
               |  Computes Weighted Posture Index (0 - 100%) & Grade |
               +-----------------------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
        v                                                                   v
+-------------------------------+                                   +-------------------------------+
|  5. Executive Reporting & SIEM|                                   | 6. Automated Remediation Hub  |
| • Markdown Executive Report   |                                   | • Azure CLI Runbooks (az)     |
| • SIEM JSON Audit Log Export  |                                   | • AWS CLI Runbooks (aws)      |
| • ChatOps Alert Embed Cards   |                                   | • PowerShell Mitigation (.ps1)|
+-------------------------------+                                   +-------------------------------+
```

---

## Technical Highlights & Key Competencies

* **Multi-Cloud CIS Benchmark Auditing:** Automated rule evaluators mapped directly to official CIS Benchmark controls across 5 core security pillars: Identity & Access Management (IAM), Cloud Storage, Network Security Groups (NSGs), Compute Workloads, and Centralized Logging.
* **MITRE ATT&CK for Cloud Correlation:** Every evaluated finding is correlated with adversary tactics and techniques (e.g., T1078.004 Cloud Accounts, T1530 Data from Cloud Storage, T1190 Exploit Public Application, T1562.008 Disable Cloud Logs).
* **Weighted Posture Scoring Index:** Calculates an enterprise-level compliance metric (0–100%) incorporating severity-weighted penalty algorithms (Critical: 15pts, High: 8pts, Medium: 4pts) and assigns letter grades (A through F).
* **Automated Remediation Orchestrator:** Generates ready-to-run shell scripts (`remediate_all.sh`) and PowerShell playbooks (`remediate_all.ps1`) providing single-click remediation via Azure CLI (`az`) and AWS CLI (`aws`).
* **SIEM & Data Lake Ingestion:** Produces structured, timestamped JSON compliance audit trails (`reports/cspm_findings.json`) designed for Splunk, Microsoft Sentinel, and Elastic SIEM ingestion.
* **ChatOps Security Broadcasting:** Real-time webhook integration dispatches rich posture embed summary cards to Discord and Slack channels upon audit completion.

---

## Evaluated CIS Benchmark Control Matrix

| Rule ID | Category | Severity | CIS Control | MITRE ATT&CK | Description |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `IAM-CIS-1.1` | **IDENTITY** | `CRITICAL` | CIS 1.1 | T1078.004 | Enforce Multi-Factor Authentication (MFA) on root accounts |
| `IAM-CIS-1.2` | **IDENTITY** | `HIGH` | CIS 1.16 | T1098 | Disallow full `*` wildcard administrative IAM policies |
| `IAM-CIS-1.3` | **IDENTITY** | `MEDIUM` | CIS 1.4 | T1078.004 | Enforce access key rotation every 90 days or less |
| `STORAGE-CIS-2.1` | **STORAGE** | `CRITICAL` | CIS 2.1.5 | T1530 | Block public anonymous read access on S3 & Blob storage |
| `STORAGE-CIS-2.2` | **STORAGE** | `HIGH` | CIS 2.1.1 | T1005 | Enforce Server-Side Encryption (SSE) at rest |
| `STORAGE-CIS-2.3` | **STORAGE** | `MEDIUM` | CIS 2.1.2 | T1040 | Enforce secure HTTPS/TLS transport for all storage endpoints |
| `NET-CIS-3.1` | **NETWORK** | `CRITICAL` | CIS 5.2.1 | T1133 | Restrict inbound RDP (port 3389) from `0.0.0.0/0` |
| `NET-CIS-3.2` | **NETWORK** | `HIGH` | CIS 5.2.2 | T1133 | Restrict inbound SSH (port 22) from `0.0.0.0/0` |
| `NET-CIS-3.3` | **NETWORK** | `CRITICAL` | CIS 5.2.3 | T1190 | Restrict database ports (3306, 5432, 1433) from public ingress |
| `COMPUTE-CIS-4.1` | **COMPUTE** | `HIGH` | CIS 7.1 | T1005 | Enforce disk encryption on virtual machine OS/data disks |
| `COMPUTE-CIS-4.2` | **COMPUTE** | `MEDIUM` | CIS 7.4 | T1190 | Restrict direct public IP addresses on workload VMs |
| `LOG-CIS-5.1` | **LOGGING** | `CRITICAL` | CIS 3.1 | T1562.008 | Enforce central activity logging with >= 90 days retention |

---

## Verification & Audit Evidence

### 1. Terminal Compliance Dashboard
```text
==============================================================================
    CLOUD SECURITY POSTURE MANAGEMENT (CSPM) & CIS BENCHMARK AUDITOR
==============================================================================
 Timestamp                : 2026-10-18T14:03:45.514047Z
 Cloud Resources Scanned  : 12
 Security Rules Evaluated : 27
 Controls Passed          : 14 [✓]
 Controls Failed          : 13 [✗]
------------------------------------------------------------------------------
 CRITICAL Violations      : 5
 HIGH Severity Findings   : 4
 MEDIUM Severity Findings : 4
 LOW Severity Findings    : 0
------------------------------------------------------------------------------
 Cloud Posture Score      : 0.0 / 100
 Compliance Grade         : [ F ]
==============================================================================

[*] Domain Compliance Breakdown:
 Category        | Total  | Passed  | Failed  | Score % 
-------------------------------------------------------
 IDENTITY        | 6      | 3       | 3       | 50.0%
 STORAGE         | 9      | 5       | 4       | 55.6%
 NETWORK         | 9      | 6       | 3       | 66.7%
 COMPUTE         | 2      | 0       | 2       | 0.0%
 LOGGING         | 1      | 0       | 1       | 0.0%
-------------------------------------------------------
```

### 2. Sample Non-Compliant Finding (JSON Output)
```json
{
  "finding_id": "STORAGE-CIS-2.1-stgcorprawcustomers",
  "rule_id": "STORAGE-CIS-2.1",
  "title": "Cloud Storage Buckets & Containers Must Block Public Anonymous Read Access",
  "severity": "CRITICAL",
  "category": "STORAGE",
  "provider": "AZURE",
  "resource_name": "stgcorprawcustomers",
  "resource_id": "/subscriptions/sub-corp-prod-01/resourceGroups/rg-customer-data/providers/Microsoft.Storage/storageAccounts/stgcorprawcustomers",
  "status": "FAIL",
  "cis_control": "CIS 2.1.5",
  "mitre_technique": "T1530",
  "rationale": "CRITICAL: Storage account / bucket allows anonymous internet users to read or download objects.",
  "remediation_cli": "az storage account update --name stgcorprawcustomers --allow-blob-public-access false"
}
```

---

## Repository Structure

```text
cloud-security-posture-auditor/
├── sample_cloud_state/
│   └── enterprise_cloud_inventory.json   # Multi-cloud enterprise resource dataset (Azure & AWS)
├── rules/                                # Modular CIS Benchmark rule evaluators
│   ├── __init__.py                       # Rule registry
│   ├── base.py                           # Abstract BaseRule interface
│   ├── iam_rules.py                      # Identity & Access Management checks (CIS Section 1)
│   ├── storage_rules.py                  # S3 & Blob storage security checks (CIS Section 2)
│   ├── network_rules.py                  # NSG & firewall boundary checks (CIS Section 3/5)
│   ├── compute_rules.py                  # VM disk encryption & public IP checks (CIS Section 7)
│   └── logging_rules.py                  # Activity logging & retention checks (CIS Section 3)
├── reports/                              # Automated compliance audit output directory
│   ├── CSPM_AUDIT_REPORT.md              # Executive Markdown compliance report
│   └── cspm_findings.json                # SIEM-ready structured audit telemetry
├── models.py                             # Data schemas (CloudResource, Finding, Severity, Grade)
├── cloud_collector.py                    # Multi-source inventory collector (Live SDK + Mock State)
├── scanner.py                            # Core CIS evaluation engine
├── scorer.py                             # Weighted Posture Score & Grade calculator
├── remediation.py                        # Automated CLI & PowerShell remediation generator
├── reporter.py                           # Markdown & JSON reporting engine
├── notifier.py                           # ChatOps Discord/Slack webhook broadcaster
├── main.py                               # CLI entry point
├── remediate_all.sh                      # Generated Bash remediation runbook
├── remediate_all.ps1                     # Generated PowerShell remediation runbook
├── requirements.txt                      # Project dependencies
└── README.md                             # Technical documentation
```

---

## Getting Started & Execution

### Prerequisites
* Python 3.10+
* Virtual Environment (`venv`)

### 1. Setup & Installation
```bash
git clone https://github.com/ravishkarathnayaka/cloud-security-posture-auditor.git
cd cloud-security-posture-auditor

python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Run the Compliance Scan
Audit the cloud environment and generate all reports:
```bash
python main.py --remediate
```

### 3. Review Generated Artifacts
* **Executive Markdown Report:** Open `reports/CSPM_AUDIT_REPORT.md`
* **Machine-Readable JSON Log:** Inspect `reports/cspm_findings.json`
* **Automated Remediation Script:** Inspect `remediate_all.sh` or `remediate_all.ps1`

### 4. Optional: Dispatch ChatOps Alert Card
Set your webhook URL in `.env` or pass via environment:
```bash
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/your_webhook_id/your_token"
python main.py --notify
```
