import time
import math
from collections import deque


class Baseline:
    """
    Tracks per-second request counts over a rolling 30-minute window.
    Recalculates mean and stddev every 60 seconds.
    Maintains per-hour slots and prefers current hour's data when available.
    """

    def __init__(self, config):
        self.window_minutes = config.get("baseline_window_minutes", 30)
        self.recalc_interval = config.get("baseline_recalc_interval_seconds", 60)
        self.min_samples = config.get("baseline_min_samples", 10)
        self.floor_mean = config.get("baseline_floor_mean", 1.0)
        self.floor_stddev = config.get("baseline_floor_stddev", 0.5)

        # Rolling window of per-second counts
        # Max size = 30 minutes * 60 seconds
        self.max_size = self.window_minutes * 60
        self.counts = deque(maxlen=self.max_size)

        # Per-hour slots: {hour: [per-second counts]}
        self.hourly_slots = {}

        # Current calculated values
        self.effective_mean = self.floor_mean
        self.effective_stddev = self.floor_stddev

        # Error rate baseline
        self.error_counts = deque(maxlen=self.max_size)
        self.effective_error_mean = 0.0

        # Timing
        self.last_recalc_time = time.time()
        self.start_time = time.time()

        # Audit log callback (set by main.py)
        self.audit_log = None

    def record(self, count, error_count=0):
        """
        Record a per-second request count and error count.
        Called every second by main.py.
        """
        self.counts.append(count)
        self.error_counts.append(error_count)

        # Store in hourly slot
        current_hour = time.localtime().tm_hour
        if current_hour not in self.hourly_slots:
            self.hourly_slots[current_hour] = deque(maxlen=self.max_size)
        self.hourly_slots[current_hour].append(count)

        # Recalculate if interval has passed
        now = time.time()
        if now - self.last_recalc_time >= self.recalc_interval:
            self.recalculate()
            self.last_recalc_time = now

    def recalculate(self):
        """
        Recalculate mean and stddev.
        Prefer current hour's data if it has enough samples.
        """
        current_hour = time.localtime().tm_hour
        hourly_data = self.hourly_slots.get(current_hour, deque())

        # Use hourly data if it has enough samples
        if len(hourly_data) >= self.min_samples:
            data = list(hourly_data)
        elif len(self.counts) >= self.min_samples:
            data = list(self.counts)
        else:
            # Not enough data yet, keep floor values
            return

        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        stddev = math.sqrt(variance)

        # Apply floor values
        self.effective_mean = max(mean, self.floor_mean)
        self.effective_stddev = max(stddev, self.floor_stddev)

        # Recalculate error baseline
        if len(self.error_counts) >= self.min_samples:
            error_data = list(self.error_counts)
            self.effective_error_mean = sum(error_data) / len(error_data)

        # Write to audit log
        if self.audit_log:
            self.audit_log(
                action="BASELINE_RECALC",
                ip="-",
                condition=f"hour={current_hour}",
                rate=self.effective_mean,
                baseline=self.effective_stddev,
                duration="-"
            )

    def get_zscore(self, current_rate):
        """
        Calculate z-score for a given rate.
        Z-score = how many standard deviations away from the mean.
        """
        if self.effective_stddev == 0:
            return 0.0
        return (current_rate - self.effective_mean) / self.effective_stddev

    def is_anomalous(self, current_rate, zscore_threshold, multiplier_threshold):
        """
        Returns (is_anomalous, reason) tuple.
        Fires if z-score > threshold OR rate > 5x mean.
        """
        zscore = self.get_zscore(current_rate)

        if zscore > zscore_threshold:
            return True, f"zscore={zscore:.2f}"

        if current_rate > multiplier_threshold * self.effective_mean:
            return True, f"rate={current_rate:.2f} > {multiplier_threshold}x mean={self.effective_mean:.2f}"

        return False, ""

    def is_error_surge(self, ip_error_rate, multiplier):
        """
        Returns True if IP error rate is 3x the baseline error rate.
        """
        if self.effective_error_mean == 0:
            return False
        return ip_error_rate > multiplier * self.effective_error_mean
