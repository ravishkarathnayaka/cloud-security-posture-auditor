"""
scorer.py - Calculates enterprise Cloud Security Posture Index (CSPI) and domain scores.
"""

from typing import List, Dict
from datetime import datetime
from models import Finding, ComplianceStatus, Severity, ResourceCategory, CategoryScore, PostureSummary


class PostureScorer:
    """Calculates weighted security posture metrics and compliance grading."""

    # Severity weights for penalty calculations
    SEVERITY_PENALTIES = {
        Severity.CRITICAL: 15.0,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 4.0,
        Severity.LOW: 1.0,
        Severity.INFORMATIONAL: 0.0
    }

    @classmethod
    def calculate_summary(cls, total_resources: int, findings: List[Finding]) -> PostureSummary:
        total_checks = len(findings)
        passed_findings = [f for f in findings if f.status == ComplianceStatus.PASS]
        failed_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]

        critical = len([f for f in failed_findings if f.severity == Severity.CRITICAL])
        high = len([f for f in failed_findings if f.severity == Severity.HIGH])
        medium = len([f for f in failed_findings if f.severity == Severity.MEDIUM])
        low = len([f for f in failed_findings if f.severity == Severity.LOW])

        # Category scores
        category_map: Dict[ResourceCategory, List[Finding]] = {}
        for f in findings:
            category_map.setdefault(f.category, []).append(f)

        category_scores: Dict[str, CategoryScore] = {}
        for cat, cat_findings in category_map.items():
            cat_total = len(cat_findings)
            cat_passed = len([f for f in cat_findings if f.status == ComplianceStatus.PASS])
            cat_failed = cat_total - cat_passed
            cat_pct = round((cat_passed / cat_total) * 100, 1) if cat_total > 0 else 100.0
            category_scores[cat.value] = CategoryScore(
                category=cat,
                total_checks=cat_total,
                passed_checks=cat_passed,
                failed_checks=cat_failed,
                score_percentage=cat_pct
            )

        # Baseline weighted composite score (100 base minus severity penalties)
        total_penalty = sum(cls.SEVERITY_PENALTIES.get(f.severity, 0.0) for f in failed_findings)
        composite_score = max(0.0, round(100.0 - total_penalty, 1))

        # Assign letter grade
        if composite_score >= 90.0:
            grade = "A"
        elif composite_score >= 80.0:
            grade = "B"
        elif composite_score >= 70.0:
            grade = "C"
        elif composite_score >= 60.0:
            grade = "D"
        else:
            grade = "F"

        return PostureSummary(
            timestamp=datetime.utcnow().isoformat() + "Z",
            total_resources_scanned=total_resources,
            total_rules_evaluated=total_checks,
            total_passed=len(passed_findings),
            total_failed=len(failed_findings),
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            composite_posture_score=composite_score,
            posture_grade=grade,
            category_scores=category_scores,
            findings=findings
        )
