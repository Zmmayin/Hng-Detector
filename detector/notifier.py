import requests
import json
import time
import os

class Notifier:
    """
    Sends Slack alerts for bans, unbans, and global anomalies.
    Webhook URL is loaded from config.
    """

    def __init__(self, config):
        self.webhook_url = (
		os.environ.get("SLACK_WEBHOOK_URL") or
		config.get("slack_webhook_url", "")
	)
        self.enabled = bool(self.webhook_url) and \
            self.webhook_url != "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

        if not self.enabled:
            print("[notifier] Slack webhook not configured — alerts disabled")
        else:
            print("[notifier] Slack alerts enabled")

    def send_ban_alert(self, ip, reason, rate, baseline_mean, duration):
        """
        Send a Slack alert when an IP is banned.
        Must fire within 10 seconds of detection.
        """
        duration_str = f"{duration}s" if duration != -1 else "permanent"

        message = {
            "text": "🚨 *IP BANNED*",
            "attachments": [
                {
                    "color": "#FF0000",
                    "fields": [
                        {"title": "IP Address",
                         "value": ip,
                         "short": True},
                        {"title": "Condition",
                         "value": reason,
                         "short": True},
                        {"title": "Current Rate",
                         "value": f"{rate:.2f} req/s",
                         "short": True},
                        {"title": "Baseline Mean",
                         "value": f"{baseline_mean:.2f} req/s",
                         "short": True},
                        {"title": "Ban Duration",
                         "value": duration_str,
                         "short": True},
                        {"title": "Timestamp",
                         "value": time.strftime("%Y-%m-%d %H:%M:%S UTC",
                                                time.gmtime()),
                         "short": True},
                    ],
                }
            ],
        }

        self._send(message)

    def send_unban_alert(self, ip, reason, duration, ban_count):
        """
        Send a Slack alert when an IP is unbanned.
        """
        message = {
            "text": "✅ *IP UNBANNED*",
            "attachments": [
                {
                    "color": "#00FF00",
                    "fields": [
                        {"title": "IP Address",
                         "value": ip,
                         "short": True},
                        {"title": "Original Reason",
                         "value": reason,
                         "short": True},
                        {"title": "Ban Duration Served",
                         "value": f"{duration}s",
                         "short": True},
                        {"title": "Total Ban Count",
                         "value": str(ban_count),
                         "short": True},
                        {"title": "Timestamp",
                         "value": time.strftime("%Y-%m-%d %H:%M:%S UTC",
                                                time.gmtime()),
                         "short": True},
                    ],
                }
            ],
        }

        self._send(message)

    def send_global_alert(self, reason, rate, baseline_mean):
        """
        Send a Slack alert for a global traffic anomaly.
        No IP ban — alert only.
        """
        message = {
            "text": "⚠️ *GLOBAL TRAFFIC ANOMALY*",
            "attachments": [
                {
                    "color": "#FFA500",
                    "fields": [
                        {"title": "Condition",
                         "value": reason,
                         "short": True},
                        {"title": "Current Global Rate",
                         "value": f"{rate:.2f} req/s",
                         "short": True},
                        {"title": "Baseline Mean",
                         "value": f"{baseline_mean:.2f} req/s",
                         "short": True},
                        {"title": "Timestamp",
                         "value": time.strftime("%Y-%m-%d %H:%M:%S UTC",
                                                time.gmtime()),
                         "short": True},
                    ],
                }
            ],
        }

        self._send(message)

    def _send(self, message):
        """
        Send a message to Slack webhook.
        Fails silently so alerts never crash the daemon.
        """
        if not self.enabled:
            print(f"[notifier] Slack disabled — would have sent: "
                  f"{message['text']}")
            return

        try:
            response = requests.post(
                self.webhook_url,
                data=json.dumps(message),
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            if response.status_code != 200:
                print(
                    f"[notifier] Slack error: {response.status_code} "
                    f"{response.text}"
                )
        except requests.exceptions.RequestException as e:
            print(f"[notifier] Slack request failed: {e}")
