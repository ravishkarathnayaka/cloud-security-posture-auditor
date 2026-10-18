"""
notifier.py - Dispatches real-time ChatOps security posture alert cards to Discord or Slack.
"""

import os
import json
from models import PostureSummary


class ChatOpsNotifier:
    """Dispatches executive posture audit embed cards to SOC ChatOps channels."""

    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or os.getenv("DISCORD_WEBHOOK_URL", "")

    def dispatch(self, summary: PostureSummary) -> bool:
        """Sends a rich ChatOps embed card with posture score and critical findings."""
        if not self.webhook_url:
            print("[i] ChatOps dispatch: DISCORD_WEBHOOK_URL not configured. Notification skipped.")
            return False

        color = 0xdc2626 if summary.composite_posture_score < 70 else 0x16a34a

        payload = {
            "username": "Cloud Security Posture (CSPM) Auditor",
            "embeds": [
                {
                    "title": "☁️ Cloud Security Posture & CIS Benchmark Audit Complete",
                    "description": (
                        f"An automated multi-cloud baseline audit was completed.\n"
                        f"**Posture Score:** `{summary.composite_posture_score} / 100` | **Grade:** `{summary.posture_grade}`"
                    ),
                    "color": color,
                    "fields": [
                        {"name": "Total Assets", "value": str(summary.total_resources_scanned), "inline": True},
                        {"name": "Passing Rules", "value": f"{summary.total_passed} [✓]", "inline": True},
                        {"name": "Failing Rules", "value": f"{summary.total_failed} [✗]", "inline": True},
                        {"name": "Critical Violations", "value": str(summary.critical_findings), "inline": True},
                        {"name": "High Findings", "value": str(summary.high_findings), "inline": True},
                        {"name": "Medium Findings", "value": str(summary.medium_findings), "inline": True}
                    ],
                    "footer": {
                        "text": f"Audit Timestamp: {summary.timestamp}"
                    }
                }
            ]
        }

        try:
            import urllib.request
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "CSPM-Auditor/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                print(f"[✓] ChatOps posture card dispatched successfully (HTTP {response.status}).")
                return True
        except Exception as e:
            print(f"[!] ChatOps dispatch warning: {e}")
            return False
