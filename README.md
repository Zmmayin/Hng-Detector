# HNG Anomaly Detection Engine

A real-time DDoS and anomaly detection daemon built alongside Nextcloud on Docker. It watches all incoming HTTP traffic, learns normal patterns, and automatically blocks suspicious IPs using iptables.

---

## Live Links

| Resource | URL |
|----------|-----|
| Server IP | http://52.23.154.241 |
| Metrics Dashboard | http://hng-detector.duckdns.org:8080 |

---

## Language Choice

**Python** — chosen because:
- Rich standard library (`collections.deque`, `statistics`, `subprocess`) covers everything needed without external rate-limiting libraries
- `threading` module makes it easy to run monitor, baseline recorder, unbanner and dashboard concurrently
- Readable code makes the detection logic easy to audit and verify
- Fast enough for the traffic volumes this tool handles

---

## How the Sliding Window Works

Two deque-based windows track request rates — one per IP, one global — over the last 60 seconds.

Every time a request comes in, its timestamp is appended to the deque. Before calculating the rate, old timestamps are evicted from the left:

    def _evict(self, window, now):
        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

Rate calculation:

    def get_ip_rate(self, ip):
        now = time.time()
        self._evict(self.ip_windows[ip], now)
        return len(self.ip_windows[ip]) / self.window_seconds

This gives requests per second over the last 60 seconds. No rate-limiting libraries used — pure deque logic.

---

## How the Baseline Works

The baseline learns what normal traffic looks like using a rolling 30-minute window of per-second request counts.

**Window size:** 30 minutes = 1800 per-second samples maximum

    self.max_size = 30 * 60
    self.counts = deque(maxlen=self.max_size)

**Recalculation interval:** Every 60 seconds

    if now - self.last_recalc_time >= 60:
        self.recalculate()
        self.last_recalc_time = now

**Per-hour slots:** The baseline maintains separate data per hour and prefers the current hour when it has enough samples:

    current_hour = time.localtime().tm_hour
    if len(hourly_data) >= self.min_samples:
        data = list(hourly_data)
    else:
        data = list(self.counts)

**Floor values:** Prevent false positives when traffic is very low:

    self.effective_mean   = max(mean, 1.0)
    self.effective_stddev = max(stddev, 0.5)

**Anomaly thresholds:**

    zscore = (current_rate - mean) / stddev
    if zscore > 3.0: ANOMALY
    if current_rate > 5 * mean: ANOMALY

---

## Setup Instructions

### 1. Provision a VPS

- Minimum: 2 vCPU, 2GB RAM
- OS: Ubuntu 22.04 LTS
- Open ports: 22, 80, 443, 8080

### 2. Install Docker

    sudo apt update && sudo apt upgrade -y
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    newgrp docker

### 3. Clone the repository

    git clone git@github.com:Zmmayin/Hng-Detector.git
    cd Hng-Detector

### 4. Configure environment

    cat > .env << ENVEOF
    SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
    ENVEOF
    cp detector/config.yaml.example detector/config.yaml

### 5. Create log directory

    mkdir -p logs

### 6. Start the stack

    docker compose up --build -d

### 7. Verify everything is running

    docker compose ps

### 8. Access the dashboard

    http://YOUR_SERVER_IP:8080

---

## Repository Structure

    detector/
      main.py
      monitor.py
      baseline.py
      detector.py
      blocker.py
      unbanner.py
      notifier.py
      dashboard.py
      config.yaml.example
      requirements.txt
    nginx/
      nginx.conf
    docs/
      architecture.png
    screenshots/
    README.md

---

## GitHub Repository

[Hng-Detector](https://github.com/Zmmayin/Hng-Detector)

---

## Blog Post

[How I Built a Real-Time DDoS Detection Engine from Scratch](https://medium.com/@eifelowo/how-i-built-a-real-time-ddos-detection-engine-from-scratch-6083ed94aece)
