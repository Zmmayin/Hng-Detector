import subprocess
import time
import json
import os


BAN_FILE = "/var/log/detector/banned_ips.json"


class Blocker:
    def __init__(self, config, audit_log=None):
        self.audit_log = audit_log
        self.ban_schedule = config.get("ban_schedule", [600, 1800, 7200, -1])
        self.banned_ips = {}
        self._load_bans()

    def _load_bans(self):
        """Load existing bans from disk on startup."""
        try:
            if os.path.exists(BAN_FILE):
                with open(BAN_FILE, "r") as f:
                    self.banned_ips = json.load(f)
                # Reapply iptables rules
                for ip in self.banned_ips:
                    self._add_iptables_rule(ip)
                print(f"[blocker] Loaded {len(self.banned_ips)} bans from disk")
        except Exception as e:
            print(f"[blocker] Failed to load bans: {e}")
            self.banned_ips = {}

    def _save_bans(self):
        """Save current bans to disk."""
        try:
            os.makedirs(os.path.dirname(BAN_FILE), exist_ok=True)
            with open(BAN_FILE, "w") as f:
                json.dump(self.banned_ips, f)
        except Exception as e:
            print(f"[blocker] Failed to save bans: {e}")

    def ban(self, ip, reason, rate, baseline_mean):
        if ip in self.banned_ips:
            return

        ban_count = self._get_ban_count(ip)
        duration = self.ban_schedule[
            min(ban_count, len(self.ban_schedule) - 1)
        ]

        success = self._add_iptables_rule(ip)
        if not success:
            return

        self.banned_ips[ip] = {
            "ban_count": ban_count + 1,
            "banned_at": time.time(),
            "duration": duration,
            "reason": reason,
        }

        self._save_bans()

        duration_str = f"{duration}s" if duration != -1 else "permanent"
        print(
            f"[blocker] Banned {ip} | reason={reason} | "
            f"rate={rate:.2f} | duration={duration_str}"
        )

        if self.audit_log:
            self.audit_log(
                action="BAN",
                ip=ip,
                condition=reason,
                rate=rate,
                baseline=baseline_mean,
                duration=duration_str,
            )

    def unban(self, ip):
        if ip not in self.banned_ips:
            return

        success = self._remove_iptables_rule(ip)
        if not success:
            return

        ban_info = self.banned_ips.pop(ip)
        self._save_bans()

        print(f"[blocker] Unbanned {ip}")

        if self.audit_log:
            self.audit_log(
                action="UNBAN",
                ip=ip,
                condition=ban_info["reason"],
                rate=0,
                baseline=0,
                duration="-",
            )

    def is_banned(self, ip):
        return ip in self.banned_ips

    def get_banned_ips(self):
        return dict(self.banned_ips)

    def _get_ban_count(self, ip):
        if ip in self.banned_ips:
            return self.banned_ips[ip]["ban_count"]
        return 0

    def _add_iptables_rule(self, ip):
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"[blocker] iptables ban failed for {ip}: {e.stderr}")
            return False

    def _remove_iptables_rule(self, ip):
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"[blocker] iptables unban failed for {ip}: {e.stderr}")
            return False
