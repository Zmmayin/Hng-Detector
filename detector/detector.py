import time
from collections import deque, defaultdict


class Detector:
    """
    Tracks per-IP and global request rates using deque-based
    sliding windows over the last 60 seconds.
    Flags anomalies using z-score and rate multiplier thresholds.
    """

    def __init__(self, config, baseline):
        self.window_seconds = config.get("sliding_window_seconds", 60)
        self.zscore_threshold = config.get("zscore_threshold", 3.0)
        self.rate_multiplier = config.get("rate_multiplier_threshold", 5.0)
        self.error_rate_multiplier = config.get("error_rate_multiplier", 3.0)
        self.baseline = baseline

        # Per-IP sliding windows
        # {ip: deque of timestamps}
        self.ip_windows = defaultdict(deque)

        # Per-IP error sliding windows
        # {ip: deque of timestamps}
        self.ip_error_windows = defaultdict(deque)

        # Global sliding window
        self.global_window = deque()

    def record_request(self, log_entry):
        """
        Record a request from a parsed log entry.
        Evicts timestamps outside the sliding window.
        """
        ip = log_entry["source_ip"]
        status = log_entry["status"]
        now = time.time()

        # Add to per-IP window
        self.ip_windows[ip].append(now)

        # Add to global window
        self.global_window.append(now)

        # Track errors (4xx/5xx)
        if status >= 400:
            self.ip_error_windows[ip].append(now)

        # Evict old timestamps
        self._evict(self.ip_windows[ip], now)
        self._evict(self.global_window, now)
        self._evict(self.ip_error_windows[ip], now)

    def _evict(self, window, now):
        """
        Remove timestamps older than the sliding window.
        Deque eviction from the left — oldest first.
        """
        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

    def get_ip_rate(self, ip):
        """
        Get current request rate for an IP in requests/second.
        """
        now = time.time()
        self._evict(self.ip_windows[ip], now)
        return len(self.ip_windows[ip]) / self.window_seconds

    def get_global_rate(self):
        """
        Get current global request rate in requests/second.
        """
        now = time.time()
        self._evict(self.global_window, now)
        return len(self.global_window) / self.window_seconds

    def get_ip_error_rate(self, ip):
        """
        Get current error rate for an IP in requests/second.
        """
        now = time.time()
        self._evict(self.ip_error_windows[ip], now)
        return len(self.ip_error_windows[ip]) / self.window_seconds

    def get_top_ips(self, n=10):
        """
        Return top N IPs by current request rate.
        """
        now = time.time()
        rates = {}
        for ip in self.ip_windows:
            self._evict(self.ip_windows[ip], now)
            rates[ip] = len(self.ip_windows[ip]) / self.window_seconds

        # Sort by rate descending
        return sorted(rates.items(), key=lambda x: x[1], reverse=True)[:n]

    def check_ip(self, ip, banned_ips):
        """
        Check if an IP is anomalous.
        Returns (is_anomalous, reason, rate) tuple.
        Tightens thresholds if IP has an error surge.
        """
        if ip in banned_ips:
            return False, "", 0.0

        rate = self.get_ip_rate(ip)
        error_rate = self.get_ip_error_rate(ip)

        # Tighten thresholds if error surge detected
        if self.baseline.is_error_surge(error_rate, self.error_rate_multiplier):
            zscore_threshold = self.zscore_threshold * 0.5
            rate_multiplier = self.rate_multiplier * 0.5
        else:
            zscore_threshold = self.zscore_threshold
            rate_multiplier = self.rate_multiplier

        anomalous, reason = self.baseline.is_anomalous(
            rate, zscore_threshold, rate_multiplier
        )

        return anomalous, reason, rate

    def check_global(self):
        """
        Check if global traffic is anomalous.
        Returns (is_anomalous, reason, rate) tuple.
        """
        rate = self.get_global_rate()

        anomalous, reason = self.baseline.is_anomalous(
            rate, self.zscore_threshold, self.rate_multiplier
        )

        return anomalous, reason, rate
