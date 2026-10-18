# Executive Cloud Security Posture & CIS Benchmark Audit Report

**Audit Execution Timestamp:** `2026-10-18T14:03:45.514047Z`  
**Cloud Environment:** Multi-Cloud Tenant (Azure Subscriptions & AWS Accounts)  
**Composite Posture Score:** **`0.0 / 100`** | **Grade:** **`F`**  

---

## 1. Executive Summary & Compliance Posture

An automated security baseline audit was conducted across multi-cloud infrastructure assets against the **Center for Internet Security (CIS) Benchmarks (v3.0.0)** and the **MITRE ATT&CK for Cloud Matrix**.

* **Total Cloud Assets Audited:** 12
* **Total Security Controls Checked:** 27
* **Passing Controls:** 14 (51.9%)
* **Failing Controls:** 13 (48.1%)

### Vulnerability Severity Breakdown

* **CRITICAL Severity:** `5` findings (Immediate account takeover, public database exposure, or missing central logs)
* **HIGH Severity:** `4` findings (Wildcard admin IAM roles, unencrypted disks, public SSH)
* **MEDIUM Severity:** `4` findings (Unrotated credentials, unencrypted transit HTTP)
* **LOW Severity:** `0` findings

---

## 2. Security Domain Compliance Scorecard

| Security Domain | Evaluated Checks | Compliant (Pass) | Non-Compliant (Fail) | Compliance Score |
| :--- | :---: | :---: | :---: | :---: |
| **IDENTITY** | 6 | 3 | 3 | **50.0%** |
| **STORAGE** | 9 | 5 | 4 | **55.6%** |
| **NETWORK** | 9 | 6 | 3 | **66.7%** |
| **COMPUTE** | 2 | 0 | 2 | **0.0%** |
| **LOGGING** | 1 | 0 | 1 | **0.0%** |

---

## 3. High-Priority Non-Compliant Findings & Remediation Matrix

| Finding ID | Severity | Resource Target | CIS Control | MITRE ATT&CK | Action Required |
| :--- | :---: | :--- | :--- | :--- | :--- |
| `IAM-CIS-1.1` | **CRITICAL** | `aws-enterprise-root-account` (AWS) | CIS 1.1 | T1078.004 | `Log into AWS console as root, navigate to IAM > Security Credentials, and enable hardware MFA.` |
| `IAM-CIS-1.2` | **HIGH** | `DevOps-Pipeline-Executor` (AWS) | CIS 1.16 | T1098 | `Replace wildcard '*' actions with granular service permissions (e.g. s3:PutObject, ec2:DescribeInstances).` |
| `IAM-CIS-1.3` | **MEDIUM** | `svc-reporting-etl` (AWS) | CIS 1.4 | T1078.004 | `Generate a new access key, deploy to workload secrets, test connectivity, and deactivate the old key.` |
| `STORAGE-CIS-2.1` | **CRITICAL** | `stgcorprawcustomers` (AZURE) | CIS 2.1.5 | T1530 | `Enforce Public Access Block and disable container-level anonymous access permissions.` |
| `STORAGE-CIS-2.3` | **MEDIUM** | `stgcorprawcustomers` (AZURE) | CIS 2.1.2 | T1040 | `Enable 'Secure transfer required' or attach an S3 bucket policy denying aws:SecureTransport: false.` |
| `STORAGE-CIS-2.2` | **HIGH** | `corp-finance-archive-2026` (AWS) | CIS 2.1.1 | T1005 | `Enable default AWS SSE-S3 / SSE-KMS or Azure Storage Service Encryption.` |
| `STORAGE-CIS-2.3` | **MEDIUM** | `corp-finance-archive-2026` (AWS) | CIS 2.1.2 | T1040 | `Enable 'Secure transfer required' or attach an S3 bucket policy denying aws:SecureTransport: false.` |
| `NET-CIS-3.1` | **CRITICAL** | `nsg-dmz-perimeter` (AZURE) | CIS 5.2.1 | T1133 | `Remove public RDP rule and enforce access via Azure Bastion, AWS Systems Manager, or VPN.` |
| `NET-CIS-3.2` | **HIGH** | `nsg-dmz-perimeter` (AZURE) | CIS 5.2.2 | T1133 | `Delete public SSH rule and route access through a hardened jump host or Session Manager.` |
| `NET-CIS-3.3` | **CRITICAL** | `nsg-prod-databases` (AZURE) | CIS 5.2.3 | T1190 | `Isolate database tier behind private subnets and allow access strictly from application gateway tiers.` |
| `COMPUTE-CIS-4.1` | **HIGH** | `vm-legacy-reporting` (AZURE) | CIS 7.1 | T1005 | `Enable Azure Disk Encryption (ADE) or attach Disk Encryption Sets (DES) using Azure Key Vault.` |
| `COMPUTE-CIS-4.2` | **MEDIUM** | `vm-legacy-reporting` (AZURE) | CIS 7.4 | T1190 | `Disassociate the Public IP from the VM network interface and route egress traffic via a NAT Gateway.` |
| `LOG-CIS-5.1` | **CRITICAL** | `azure-activity-log-profile` (AZURE) | CIS 3.1 | T1562.008 | `Create an Azure Log Profile or AWS CloudTrail multi-region trail configured with S3 and CloudWatch delivery.` |

---

## 4. Technical Findings Deep-Dive

### 1. [CRITICAL] Root Account Must Have Multi-Factor Authentication (MFA) Enabled
* **Affected Resource:** `aws-enterprise-root-account` (`arn:aws:iam::123456789012:root`)
* **Provider & Domain:** `AWS` | `IDENTITY`
* **CIS Benchmark:** `CIS 1.1` - *Ensure MFA is enabled for the 'root' user account*
* **MITRE ATT&CK:** `T1078.004` (*Valid Accounts: Cloud Accounts*)
* **Audit Rationale:** CRITICAL: The root account is active without Multi-Factor Authentication (MFA).
* **Recommended Remediation:** Log into AWS console as root, navigate to IAM > Security Credentials, and enable hardware MFA.

**CLI Remediation Command:**
```bash
aws iam enable-mfa-device --user-name root --serial-number <MFA_SERIAL>
```

### 2. [HIGH] IAM Policies Must Not Grant Wildcard Full Administrative Privileges
* **Affected Resource:** `DevOps-Pipeline-Executor` (`arn:aws:iam::123456789012:role/DevOps-Pipeline-Executor`)
* **Provider & Domain:** `AWS` | `IDENTITY`
* **CIS Benchmark:** `CIS 1.16` - *Ensure IAM policies that allow full '*:*' administrative privileges are not created*
* **MITRE ATT&CK:** `T1098` (*Account Manipulation*)
* **Audit Rationale:** HIGH: Role has inline/attached policies granting full '*:*' wildcard administrative control.
* **Recommended Remediation:** Replace wildcard '*' actions with granular service permissions (e.g. s3:PutObject, ec2:DescribeInstances).

**CLI Remediation Command:**
```bash
aws iam delete-role-policy --role-name DevOps-Pipeline-Executor --policy-name OverlyPermissiveAdminAccess
```

### 3. [MEDIUM] User Access Keys Must Be Rotated Every 90 Days or Less
* **Affected Resource:** `svc-reporting-etl` (`arn:aws:iam::123456789012:user/svc-reporting-etl`)
* **Provider & Domain:** `AWS` | `IDENTITY`
* **CIS Benchmark:** `CIS 1.4` - *Ensure access keys are rotated every 90 days or less*
* **MITRE ATT&CK:** `T1078.004` (*Valid Accounts: Cloud Accounts*)
* **Audit Rationale:** MEDIUM: Access key has been active for 182 days without rotation (exceeds 90-day threshold).
* **Recommended Remediation:** Generate a new access key, deploy to workload secrets, test connectivity, and deactivate the old key.

**CLI Remediation Command:**
```bash
aws iam update-access-key --user-name svc-reporting-etl --access-key-id <KEY_ID> --status Inactive
```

### 4. [CRITICAL] Cloud Storage Buckets & Containers Must Block Public Anonymous Read Access
* **Affected Resource:** `stgcorprawcustomers` (`/subscriptions/sub-corp-prod-01/resourceGroups/rg-customer-data/providers/Microsoft.Storage/storageAccounts/stgcorprawcustomers`)
* **Provider & Domain:** `AZURE` | `STORAGE`
* **CIS Benchmark:** `CIS 2.1.5` - *Ensure that Cloud Storage is not publicly accessible*
* **MITRE ATT&CK:** `T1530` (*Data from Cloud Storage Object*)
* **Audit Rationale:** CRITICAL: Storage account / bucket allows anonymous internet users to read or download objects.
* **Recommended Remediation:** Enforce Public Access Block and disable container-level anonymous access permissions.

**CLI Remediation Command:**
```bash
az storage account update --name stgcorprawcustomers --allow-blob-public-access false
```

### 5. [MEDIUM] Storage Must Enforce Secure Transfer (HTTPS/TLS Only)
* **Affected Resource:** `stgcorprawcustomers` (`/subscriptions/sub-corp-prod-01/resourceGroups/rg-customer-data/providers/Microsoft.Storage/storageAccounts/stgcorprawcustomers`)
* **Provider & Domain:** `AZURE` | `STORAGE`
* **CIS Benchmark:** `CIS 2.1.2` - *Ensure that 'Secure transfer required' is enabled for Cloud Storage*
* **MITRE ATT&CK:** `T1040` (*Network Sniffing*)
* **Audit Rationale:** MEDIUM: Unencrypted plain HTTP requests are accepted by this storage account.
* **Recommended Remediation:** Enable 'Secure transfer required' or attach an S3 bucket policy denying aws:SecureTransport: false.

**CLI Remediation Command:**
```bash
az storage account update --name stgcorprawcustomers --https-only true
```

### 6. [HIGH] Storage at Rest Must Enforce Server-Side Encryption (SSE)
* **Affected Resource:** `corp-finance-archive-2026` (`arn:aws:s3:::corp-finance-archive-2026`)
* **Provider & Domain:** `AWS` | `STORAGE`
* **CIS Benchmark:** `CIS 2.1.1` - *Ensure that all Cloud Storage accounts enforce Server-Side Encryption*
* **MITRE ATT&CK:** `T1005` (*Data from Local System*)
* **Audit Rationale:** HIGH: Storage bucket does not have default server-side encryption enabled.
* **Recommended Remediation:** Enable default AWS SSE-S3 / SSE-KMS or Azure Storage Service Encryption.

**CLI Remediation Command:**
```bash
aws s3api put-bucket-encryption --bucket corp-finance-archive-2026 --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'
```

### 7. [MEDIUM] Storage Must Enforce Secure Transfer (HTTPS/TLS Only)
* **Affected Resource:** `corp-finance-archive-2026` (`arn:aws:s3:::corp-finance-archive-2026`)
* **Provider & Domain:** `AWS` | `STORAGE`
* **CIS Benchmark:** `CIS 2.1.2` - *Ensure that 'Secure transfer required' is enabled for Cloud Storage*
* **MITRE ATT&CK:** `T1040` (*Network Sniffing*)
* **Audit Rationale:** MEDIUM: Unencrypted plain HTTP requests are accepted by this storage account.
* **Recommended Remediation:** Enable 'Secure transfer required' or attach an S3 bucket policy denying aws:SecureTransport: false.

**CLI Remediation Command:**
```bash
aws s3api put-bucket-policy --bucket corp-finance-archive-2026 --policy <ENFORCE_TLS_POLICY_JSON>
```

### 8. [CRITICAL] Network Security Groups Must Restrict Inbound RDP (Port 3389) from 0.0.0.0/0
* **Affected Resource:** `nsg-dmz-perimeter` (`/subscriptions/sub-corp-prod-01/resourceGroups/rg-network-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-dmz-perimeter`)
* **Provider & Domain:** `AZURE` | `NETWORK`
* **CIS Benchmark:** `CIS 5.2.1` - *Ensure that RDP access is restricted from the internet*
* **MITRE ATT&CK:** `T1133` (*External Remote Services*)
* **Audit Rationale:** CRITICAL: Inbound security rule 'Allow-Any-RDP' allows unauthenticated public access to RDP (3389).
* **Recommended Remediation:** Remove public RDP rule and enforce access via Azure Bastion, AWS Systems Manager, or VPN.

**CLI Remediation Command:**
```bash
az network nsg rule delete --resource-group <RG> --nsg-name nsg-dmz-perimeter --name Allow-Any-RDP
```

### 9. [HIGH] Network Security Groups Must Restrict Inbound SSH (Port 22) from 0.0.0.0/0
* **Affected Resource:** `nsg-dmz-perimeter` (`/subscriptions/sub-corp-prod-01/resourceGroups/rg-network-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-dmz-perimeter`)
* **Provider & Domain:** `AZURE` | `NETWORK`
* **CIS Benchmark:** `CIS 5.2.2` - *Ensure that SSH access is restricted from the internet*
* **MITRE ATT&CK:** `T1133` (*External Remote Services*)
* **Audit Rationale:** HIGH: Inbound security rule 'Allow-Any-SSH' allows unauthenticated public access to SSH (22).
* **Recommended Remediation:** Delete public SSH rule and route access through a hardened jump host or Session Manager.

**CLI Remediation Command:**
```bash
az network nsg rule delete --resource-group <RG> --nsg-name nsg-dmz-perimeter --name Allow-Any-SSH
```

### 10. [CRITICAL] Database Ports (MySQL, PostgreSQL, MSSQL) Must Not Be Publicly Accessible
* **Affected Resource:** `nsg-prod-databases` (`/subscriptions/sub-corp-prod-01/resourceGroups/rg-database-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-prod-databases`)
* **Provider & Domain:** `AZURE` | `NETWORK`
* **CIS Benchmark:** `CIS 5.2.3` - *Ensure that database listener ports are isolated from public ingress*
* **MITRE ATT&CK:** `T1190` (*Exploit Public-Facing Application*)
* **Audit Rationale:** CRITICAL: Inbound security rule 'Allow-MySQL-Public' opens database port 3306 to 0.0.0.0/0.
* **Recommended Remediation:** Isolate database tier behind private subnets and allow access strictly from application gateway tiers.

**CLI Remediation Command:**
```bash
az network nsg rule delete --resource-group <RG> --nsg-name nsg-prod-databases --name Allow-MySQL-Public
```

### 11. [HIGH] Virtual Machine OS and Data Disks Must Be Encrypted at Rest
* **Affected Resource:** `vm-legacy-reporting` (`/subscriptions/sub-corp-prod-01/resourceGroups/rg-compute-prod/providers/Microsoft.Compute/virtualMachines/vm-legacy-reporting`)
* **Provider & Domain:** `AZURE` | `COMPUTE`
* **CIS Benchmark:** `CIS 7.1` - *Ensure that OS and Data Disks are encrypted with Customer Managed Keys or Platform Keys*
* **MITRE ATT&CK:** `T1005` (*Data from Local System*)
* **Audit Rationale:** HIGH: Virtual Machine OS disk is unencrypted at rest.
* **Recommended Remediation:** Enable Azure Disk Encryption (ADE) or attach Disk Encryption Sets (DES) using Azure Key Vault.

**CLI Remediation Command:**
```bash
az vm encryption enable --resource-group <RG> --name vm-legacy-reporting --disk-encryption-keyvault <VAULT_NAME>
```

### 12. [MEDIUM] Virtual Machines Should Not Have Direct Public IP Addresses Attached
* **Affected Resource:** `vm-legacy-reporting` (`/subscriptions/sub-corp-prod-01/resourceGroups/rg-compute-prod/providers/Microsoft.Compute/virtualMachines/vm-legacy-reporting`)
* **Provider & Domain:** `AZURE` | `COMPUTE`
* **CIS Benchmark:** `CIS 7.4` - *Ensure that Virtual Machines do not have direct public IPv4 addresses attached*
* **MITRE ATT&CK:** `T1190` (*Exploit Public-Facing Application*)
* **Audit Rationale:** MEDIUM: VM has direct public IP '52.167.44.119' exposed to the public internet.
* **Recommended Remediation:** Disassociate the Public IP from the VM network interface and route egress traffic via a NAT Gateway.

**CLI Remediation Command:**
```bash
az network nic ip-config update --resource-group <RG> --nic-name <NIC> --name <IP_CONFIG> --remove publicIpAddress
```

### 13. [CRITICAL] Central Cloud Audit Logging Must Be Enabled with Minimum 90-Day Retention
* **Affected Resource:** `azure-activity-log-profile` (`/subscriptions/sub-corp-prod-01/providers/microsoft.insights/logprofiles/default`)
* **Provider & Domain:** `AZURE` | `LOGGING`
* **CIS Benchmark:** `CIS 3.1` - *Ensure a log profile exists and captures all activity log categories with >= 90 days retention*
* **MITRE ATT&CK:** `T1562.008` (*Impair Defenses: Disable Cloud Logs*)
* **Audit Rationale:** CRITICAL: Central cloud activity logging is disabled or has insufficient retention (< 90 days).
* **Recommended Remediation:** Create an Azure Log Profile or AWS CloudTrail multi-region trail configured with S3 and CloudWatch delivery.

**CLI Remediation Command:**
```bash
az monitor log-profiles create --name default --categories Write Delete Action --locations global eastus --days 365 --enabled true
```

---

## 5. Automated Remediation Playbook
To execute the remediation commands in batch, refer to the generated script `remediate_all.sh` or run the CLI in auto-remediation mode:
```bash
python main.py --remediate --auto-apply
```