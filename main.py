"""
main.py - CLI entry point for the Automated Cloud Security Posture Management (CSPM) Auditor.
"""

import sys
import argparse
from cloud_collector import CloudInventoryCollector
from scanner import CloudSecurityScanner
from scorer import PostureScorer
from reporter import ComplianceReporter
from remediation import RemediationGenerator
from notifier import ChatOpsNotifier


def main():
    parser = argparse.ArgumentParser(
        description="Automated Cloud Security Posture Management (CSPM) & CIS Benchmark Auditor"
    )
    parser.add_argument(
        "--inventory",
        default="sample_cloud_state/enterprise_cloud_inventory.json",
        help="Path to cloud inventory JSON file"
    )
    parser.add_argument(
        "--remediate",
        action="store_true",
        help="Generate automated remediation scripts (Bash and PowerShell)"
    )
    parser.add_argument(
        "--export-json",
        default="reports/cspm_findings.json",
        help="Export path for JSON audit log"
    )
    parser.add_argument(
        "--export-md",
        default="reports/CSPM_AUDIT_REPORT.md",
        help="Export path for Markdown executive report"
    )
    parser.add_argument(
        "--notify",
        action="store_true",
        help="Dispatch ChatOps alert card via webhook"
    )

    args = parser.parse_args()

    # Step 1: Ingest Cloud Resource Inventory
    print("[*] Ingesting cloud resources from inventory...")
    collector = CloudInventoryCollector(inventory_file=args.inventory)
    try:
        resources = collector.collect()
        print(f"[✓] Successfully ingested {len(resources)} cloud resources across Azure and AWS.")
    except Exception as e:
        print(f"[!] Error collecting cloud inventory: {e}")
        sys.exit(1)

    # Step 2: Execute CIS Benchmark & Security Evaluation
    print("[*] Running CIS Benchmark & MITRE ATT&CK security evaluators...")
    scanner = CloudSecurityScanner()
    findings = scanner.scan(resources)
    print(f"[✓] Evaluated {len(findings)} control assertions across all resources.")

    # Step 3: Compute Posture Scores & Metric Aggregations
    print("[*] Computing Cloud Security Posture Index (CSPI) and category scores...")
    summary = PostureScorer.calculate_summary(total_resources=len(resources), findings=findings)

    # Step 4: Render Visual Terminal Report
    ComplianceReporter.print_terminal_summary(summary)

    # Step 5: Export Markdown & JSON Reports
    if args.export_md:
        ComplianceReporter.export_markdown_report(summary, filepath=args.export_md)

    if args.export_json:
        ComplianceReporter.export_json(summary, filepath=args.export_json)

    # Step 6: Generate Automated Remediation Scripts if requested
    if args.remediate:
        print("[*] Generating automated remediation playbooks...")
        sh_script = RemediationGenerator.generate_shell_script(findings)
        ps_script = RemediationGenerator.generate_powershell_script(findings)

        with open("remediate_all.sh", "w", encoding="utf-8") as f:
            f.write(sh_script)
        with open("remediate_all.ps1", "w", encoding="utf-8") as f:
            f.write(ps_script)

        print("[✓] Generated Bash remediation playbook: 'remediate_all.sh'")
        print("[✓] Generated PowerShell remediation playbook: 'remediate_all.ps1'")

    # Step 7: Dispatch ChatOps Alert
    if args.notify:
        notifier = ChatOpsNotifier()
        notifier.dispatch(summary)


if __name__ == "__main__":
    main()
