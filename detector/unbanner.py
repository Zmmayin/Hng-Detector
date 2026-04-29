import time
import threading


class Unbanner:
    """
    Runs in a background thread.
    Checks banned IPs every 10 seconds and releases
    bans that have exceeded their duration.
    Sends Slack notification on every unban.
    """

    def __init__(self, blocker, notifier):
        self.blocker = blocker
        self.notifier = notifier
        self.running = False
        self.thread = None

    def start(self):
        """
        Start the unbanner in a background thread.
        """
        self.running = True
        self.thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="unbanner"
        )
        self.thread.start()
        print("[unbanner] Started background unban thread")

    def stop(self):
        """
        Stop the unbanner thread.
        """
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("[unbanner] Stopped")

    def _run(self):
        """
        Main loop — checks every 10 seconds for expired bans.
        """
        while self.running:
            try:
                self._check_bans()
            except Exception as e:
                print(f"[unbanner] Error: {e}")
            time.sleep(10)

    def _check_bans(self):
        """
        Loop through all banned IPs and unban those
        whose duration has expired.
        Permanent bans (duration=-1) are never released.
        """
        now = time.time()
        banned = self.blocker.get_banned_ips()

        for ip, ban_info in banned.items():
            duration = ban_info["duration"]

            # Skip permanent bans
            if duration == -1:
                continue

            banned_at = ban_info["banned_at"]
            elapsed = now - banned_at

            if elapsed >= duration:
                print(
                    f"[unbanner] Ban expired for {ip} "
                    f"after {duration}s — unbanning"
                )

                # Unban the IP
                self.blocker.unban(ip)

                # Send Slack notification
                self.notifier.send_unban_alert(
                    ip=ip,
                    reason=ban_info["reason"],
                    duration=duration,
                    ban_count=ban_info["ban_count"],
                )
