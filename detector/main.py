import time
import threading
import os
import yaml
from collections import defaultdict

from monitor import tail_log
from baseline import Baseline
from detector import Detector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import Dashboard


def load_config(path="config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def setup_audit_log(log_path):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def audit_log(action, ip, condition, rate, baseline, duration):
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = (
            f"[{timestamp}] {action} {ip} | "
            f"condition={condition} | "
            f"rate={rate} | "
            f"baseline={baseline} | "
            f"duration={duration}\n"
        )
        print(f"[audit] {line.strip()}")
        try:
            with open(log_path, "a") as f:
                f.write(line)
        except Exception as e:
            print(f"[audit] Failed to write log: {e}")

    return audit_log


def run_baseline_recorder(baseline, detector, interval=1.0):
    """
    Every second, count requests that arrived in the last
    1 second only — giving a true per-second count.
    This satisfies the requirement:
    'rolling 30-minute window of per-second counts'
    Attack traffic from banned IPs is naturally excluded
    because their windows are cleared on ban.
    """
    while True:
        try:
            now = time.time()
            one_second_ago = now - 1.0

            # Count requests in last 1 second from all IPs
            per_second_count = 0
            per_second_errors = 0

            for ip, window in detector.ip_windows.items():
                for ts in reversed(window):
                    if ts >= one_second_ago:
                        per_second_count += 1
                    else:
                        break  # deque is ordered, stop early

            for ip, window in detector.ip_error_windows.items():
                for ts in reversed(window):
                    if ts >= one_second_ago:
                        per_second_errors += 1
                    else:
                        break

            baseline.record(
                count=per_second_count,
                error_count=per_second_errors,
            )

        except Exception as e:
            print(f"[baseline-recorder] Error: {e}")
        time.sleep(interval)


def main():
    print("[main] Starting HNG Anomaly Detection Engine...")

    config = load_config("config.yaml")
    audit_log = setup_audit_log(config["audit_log_path"])

    notifier = Notifier(config)
    baseline = Baseline(config)
    baseline.audit_log = audit_log

    blocker = Blocker(config, audit_log=audit_log)
    detector = Detector(config, baseline)

    unbanner = Unbanner(blocker, notifier)
    dashboard = Dashboard(config, detector, blocker, baseline)

    alerted_ips = {}
    global_alerted_at = 0
    alert_cooldown = 60

    unbanner.start()
    dashboard.start()

    # Note: no blocker passed — attack traffic excluded
    # naturally via clear_ip() after each ban
    baseline_thread = threading.Thread(
        target=run_baseline_recorder,
        args=(baseline, detector),
        daemon=True,
        name="baseline-recorder",
    )
    baseline_thread.start()

    print("[main] All services started — tailing logs...")

    for entry in tail_log(config["log_path"]):
        try:
            ip = entry["source_ip"]
            now = time.time()

            detector.record_request(entry)

            if blocker.is_banned(ip):
                continue

            is_anomalous, reason, rate = detector.check_ip(
                ip, blocker.get_banned_ips()
            )

            if is_anomalous:
                last_alerted = alerted_ips.get(ip, 0)
                if now - last_alerted > alert_cooldown:
                    alerted_ips[ip] = now
                    print(
                        f"[main] ANOMALY DETECTED — IP={ip} "
                        f"rate={rate:.2f} reason={reason}"
                    )
                    blocker.ban(
                        ip=ip,
                        reason=reason,
                        rate=rate,
                        baseline_mean=baseline.effective_mean,
                    )
                    # Clear attack traffic immediately
                    # so baseline stays clean for next attack
                    detector.clear_ip(ip)

                    ban_info = blocker.get_banned_ips().get(ip, {})
                    notifier.send_ban_alert(
                        ip=ip,
                        reason=reason,
                        rate=rate,
                        baseline_mean=baseline.effective_mean,
                        duration=ban_info.get("duration", -1),
                    )

            if not hasattr(main, "_last_global_check"):
                main._last_global_check = 0

            if now - main._last_global_check >= 5:
                main._last_global_check = now
                g_anomalous, g_reason, g_rate = detector.check_global()

                if g_anomalous:
                    if now - global_alerted_at > alert_cooldown:
                        global_alerted_at = now
                        print(
                            f"[main] GLOBAL ANOMALY — "
                            f"rate={g_rate:.2f} reason={g_reason}"
                        )
                        notifier.send_global_alert(
                            reason=g_reason,
                            rate=g_rate,
                            baseline_mean=baseline.effective_mean,
                        )

        except Exception as e:
            print(f"[main] Error processing entry: {e}")
            continue


if __name__ == "__main__":
    main()
