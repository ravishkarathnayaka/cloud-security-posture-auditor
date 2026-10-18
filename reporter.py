"""
reporter.py - Generates executive Markdown reports, JSON exports, and terminal visual output.
"""

import os
import json
from models import PostureSummary, ComplianceStatus, Severity


class ComplianceReporter:
    """Formats and exports audit reports across Markdown, JSON, and terminal interfaces."""

    @staticmethod
    def print_terminal_summary(summary: PostureSummary):
        """Prints a professional, scannable terminal dashboard of the posture audit."""
        print("\n" + "=" * 78)
        print("    CLOUD SECURITY POSTURE MANAGEMENT (CSPM) & CIS BENCHMARK AUDITOR")
        print("=" * 78)
        print(f" Timestamp                : {summary.timestamp}")
        print(f" Cloud Resources Scanned  : {summary.total_resources_scanned}")
        print(f" Security Rules Evaluated : {summary.total_rules_evaluated}")
        print(f" Controls Passed          : {summary.total_passed} [✓]")
        print(f" Controls Failed          : {summary.total_failed} [✗]")
        print("-" * 78)
        print(f" CRITICAL Violations      : {summary.critical_findings}")
        print(f" HIGH Severity Findings   : {summary.high_findings}")
        print(f" MEDIUM Severity Findings : {summary.medium_findings}")
        print(f" LOW Severity Findings    : {summary.low_findings}")
        print("-" * 78)
        print(f" Cloud Posture Score      : {summary.composite_posture_score} / 100")
        print(f" Compliance Grade         : [ {summary.posture_grade} ]")
        print("=" * 78)

        print("\n[*] Domain Compliance Breakdown:")
        print(f" {'Category':<15} | {'Total':<6} | {'Passed':<7} | {'Failed':<7} | {'Score %':<8}")
        print("-" * 55)
        for cat_name, cat in summary.category_scores.items():
            print(f" {cat_name:<15} | {cat.total_checks:<6} | {cat.passed_checks:<7} | {cat.failed_checks:<7} | {cat.score_percentage}%")
        print("-" * 55)

        print("\n[*] Key Security Findings & Failures:")
        failed = [f for f in summary.findings if f.status == ComplianceStatus.FAIL]
        for idx, f in enumerate(failed, 1):
            print(f" [{idx}] [{f.severity.value}] {f.rule_id}: {f.title}")
            print(f"     • Target Resource : {f.resource_name} ({f.provider.value})")
            print(f"     • CIS Control     : {f.cis_mapping.cis_id} ({f.cis_mapping.cis_title})")
            print(f"     • MITRE ATT&CK    : {f.cis_mapping.mitre_technique_id} - {f.cis_mapping.mitre_technique_name}")
            print(f"     • Rationale       : {f.rationale}")
            print(f"     • Remediation CLI : {f.remediation_cli}\n")
        print("=" * 78)

    @staticmethod
    def export_json(summary: PostureSummary, filepath: str = "reports/cspm_findings.json"):
        """Exports full audit findings to JSON for SIEM / Data Lake ingestion."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        data = {
            "timestamp": summary.timestamp,
            "total_resources_scanned": summary.total_resources_scanned,
            "total_rules_evaluated": summary.total_rules_evaluated,
            "total_passed": summary.total_passed,
            "total_failed": summary.total_failed,
            "critical_findings": summary.critical_findings,
            "high_findings": summary.high_findings,
            "medium_findings": summary.medium_findings,
            "low_findings": summary.low_findings,
            "composite_posture_score": summary.composite_posture_score,
            "posture_grade": summary.posture_grade,
            "category_scores": {
                k: {
                    "total": v.total_checks,
                    "passed": v.passed_checks,
                    "failed": v.failed_checks,
                    "score_percentage": v.score_percentage
                } for k, v in summary.category_scores.items()
            },
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "provider": f.provider.value,
                    "resource_name": f.resource_name,
                    "resource_id": f.resource_id,
                    "status": f.status.value,
                    "cis_control": f.cis_mapping.cis_id,
                    "mitre_technique": f.cis_mapping.mitre_technique_id,
                    "rationale": f.rationale,
                    "remediation_cli": f.remediation_cli
                } for f in summary.findings
            ]
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[✓] Machine-readable audit JSON exported to: {filepath}")

    @staticmethod
    def export_markdown_report(summary: PostureSummary, filepath: str = "reports/CSPM_AUDIT_REPORT.md"):
        """Generates an executive-ready Markdown compliance report."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        failed = [f for f in summary.findings if f.status == ComplianceStatus.FAIL]

        lines = [
            "# Executive Cloud Security Posture & CIS Benchmark Audit Report",
            "",
            f"**Audit Execution Timestamp:** `{summary.timestamp}`  ",
            f"**Cloud Environment:** Multi-Cloud Tenant (Azure Subscriptions & AWS Accounts)  ",
            f"**Composite Posture Score:** **`{summary.composite_posture_score} / 100`** | **Grade:** **`{summary.posture_grade}`**  ",
            "",
            "---",
            "",
            "## 1. Executive Summary & Compliance Posture",
            "",
            "An automated security baseline audit was conducted across multi-cloud infrastructure assets against the **Center for Internet Security (CIS) Benchmarks (v3.0.0)** and the **MITRE ATT&CK for Cloud Matrix**.",
            "",
            f"* **Total Cloud Assets Audited:** {summary.total_resources_scanned}",
            f"* **Total Security Controls Checked:** {summary.total_rules_evaluated}",
            f"* **Passing Controls:** {summary.total_passed} ({round((summary.total_passed/summary.total_rules_evaluated)*100, 1)}%)",
            f"* **Failing Controls:** {summary.total_failed} ({round((summary.total_failed/summary.total_rules_evaluated)*100, 1)}%)",
            "",
            "### Vulnerability Severity Breakdown",
            "",
            f"* **CRITICAL Severity:** `{summary.critical_findings}` findings (Immediate account takeover, public database exposure, or missing central logs)",
            f"* **HIGH Severity:** `{summary.high_findings}` findings (Wildcard admin IAM roles, unencrypted disks, public SSH)",
            f"* **MEDIUM Severity:** `{summary.medium_findings}` findings (Unrotated credentials, unencrypted transit HTTP)",
            f"* **LOW Severity:** `{summary.low_findings}` findings",
            "",
            "---",
            "",
            "## 2. Security Domain Compliance Scorecard",
            "",
            "| Security Domain | Evaluated Checks | Compliant (Pass) | Non-Compliant (Fail) | Compliance Score |",
            "| :--- | :---: | :---: | :---: | :---: |"
        ]

        for cat_name, cat in summary.category_scores.items():
            lines.append(f"| **{cat_name}** | {cat.total_checks} | {cat.passed_checks} | {cat.failed_checks} | **{cat.score_percentage}%** |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. High-Priority Non-Compliant Findings & Remediation Matrix",
            "",
            "| Finding ID | Severity | Resource Target | CIS Control | MITRE ATT&CK | Action Required |",
            "| :--- | :---: | :--- | :--- | :--- | :--- |"
        ])

        for f in failed:
            lines.append(f"| `{f.rule_id}` | **{f.severity.value}** | `{f.resource_name}` ({f.provider.value}) | {f.cis_mapping.cis_id} | {f.cis_mapping.mitre_technique_id} | `{f.remediation_guidance}` |")

        lines.extend([
            "",
            "---",
            "",
            "## 4. Technical Findings Deep-Dive",
            ""
        ])

        for idx, f in enumerate(failed, 1):
            lines.extend([
                f"### {idx}. [{f.severity.value}] {f.title}",
                f"* **Affected Resource:** `{f.resource_name}` (`{f.resource_id}`)",
                f"* **Provider & Domain:** `{f.provider.value}` | `{f.category.value}`",
                f"* **CIS Benchmark:** `{f.cis_mapping.cis_id}` - *{f.cis_mapping.cis_title}*",
                f"* **MITRE ATT&CK:** `{f.cis_mapping.mitre_technique_id}` (*{f.cis_mapping.mitre_technique_name}*)",
                f"* **Audit Rationale:** {f.rationale}",
                f"* **Recommended Remediation:** {f.remediation_guidance}",
                "",
                "**CLI Remediation Command:**",
                "```bash",
                f"{f.remediation_cli}",
                "```",
                ""
            ])

        lines.extend([
            "---",
            "",
            "## 5. Automated Remediation Playbook",
            "To execute the remediation commands in batch, refer to the generated script `remediate_all.sh` or run the CLI in auto-remediation mode:",
            "```bash",
            "python main.py --remediate --auto-apply",
            "```"
        ])

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"[✓] Executive Markdown report generated at: {filepath}")
