import time
import psutil
import threading
from collections import deque
from flask import Flask, jsonify, render_template_string


# Store baseline history for the graph
# {hour: [(timestamp, mean, stddev), ...]}
baseline_history = deque(maxlen=200)


DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>HNG Anomaly Detector</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: monospace;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }
        h1 { color: #58a6ff; margin-bottom: 20px; }
        h2 { color: #58a6ff; margin: 20px 0 10px; font-size: 14px; }
        .grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 15px;
        }
        .card .label {
            font-size: 11px;
            color: #8b949e;
            margin-bottom: 5px;
        }
        .card .value {
            font-size: 24px;
            color: #58a6ff;
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border-radius: 8px;
            overflow: hidden;
        }
        th {
            background: #21262d;
            padding: 10px;
            text-align: left;
            font-size: 12px;
            color: #8b949e;
        }
        td {
            padding: 10px;
            font-size: 13px;
            border-top: 1px solid #30363d;
        }
        .banned { color: #f85149; }
        .status {
            font-size: 11px;
            color: #3fb950;
            margin-bottom: 20px;
        }
        .uptime { color: #f0883e; }
        .chart-container {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <h1>🛡️ HNG Anomaly Detection Engine</h1>
    <div class="status" id="status">Connecting...</div>

    <div class="grid">
        <div class="card">
            <div class="label">Global req/s</div>
            <div class="value" id="global-rate">-</div>
        </div>
        <div class="card">
            <div class="label">Baseline Mean</div>
            <div class="value" id="baseline-mean">-</div>
        </div>
        <div class="card">
            <div class="label">Baseline Stddev</div>
            <div class="value" id="baseline-stddev">-</div>
        </div>
        <div class="card">
            <div class="label">Banned IPs</div>
            <div class="value banned" id="banned-count">-</div>
        </div>
        <div class="card">
            <div class="label">CPU Usage</div>
            <div class="value" id="cpu">-</div>
        </div>
        <div class="card">
            <div class="label">Memory Usage</div>
            <div class="value" id="memory">-</div>
        </div>
    </div>

    <h2>Uptime</h2>
    <div class="card" style="margin-bottom:20px">
        <div class="value uptime" id="uptime">-</div>
    </div>

    <h2>Baseline Over Time</h2>
    <div class="chart-container">
        <canvas id="baselineChart" height="100"></canvas>
    </div>

    <h2>Banned IPs</h2>
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Reason</th>
                <th>Banned At</th>
                <th>Duration</th>
                <th>Ban Count</th>
            </tr>
        </thead>
        <tbody id="banned-table">
            <tr><td colspan="5">No banned IPs</td></tr>
        </tbody>
    </table>

    <h2>Top 10 Source IPs</h2>
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Rate (req/s)</th>
            </tr>
        </thead>
        <tbody id="top-ips-table">
            <tr><td colspan="2">No data yet</td></tr>
        </tbody>
    </table>

    <script>
        // Initialize baseline chart
        const ctx = document.getElementById('baselineChart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Effective Mean (req/s)',
                        data: [],
                        borderColor: '#58a6ff',
                        backgroundColor: 'rgba(88,166,255,0.1)',
                        tension: 0.3,
                        fill: true,
                    },
                    {
                        label: 'Stddev',
                        data: [],
                        borderColor: '#f0883e',
                        backgroundColor: 'rgba(240,136,62,0.1)',
                        tension: 0.3,
                        fill: false,
                    }
                ]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        labels: { color: '#c9d1d9' }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#8b949e', maxTicksLimit: 10 },
                        grid: { color: '#30363d' }
                    },
                    y: {
                        ticks: { color: '#8b949e' },
                        grid: { color: '#30363d' }
                    }
                }
            }
        });

        async function refresh() {
            try {
                const res = await fetch('/api/metrics');
                const data = await res.json();

                document.getElementById('status').textContent =
                    '● Live — Last updated: ' + new Date().toLocaleTimeString();
                document.getElementById('global-rate').textContent =
                    data.global_rate.toFixed(2);
                document.getElementById('baseline-mean').textContent =
                    data.baseline_mean.toFixed(2);
                document.getElementById('baseline-stddev').textContent =
                    data.baseline_stddev.toFixed(2);
                document.getElementById('banned-count').textContent =
                    data.banned_count;
                document.getElementById('cpu').textContent =
                    data.cpu_percent.toFixed(1) + '%';
                document.getElementById('memory').textContent =
                    data.memory_percent.toFixed(1) + '%';
                document.getElementById('uptime').textContent =
                    data.uptime;

                // Update baseline chart
                if (data.baseline_history.length > 0) {
                    chart.data.labels = data.baseline_history.map(
                        b => b.time
                    );
                    chart.data.datasets[0].data = data.baseline_history.map(
                        b => b.mean
                    );
                    chart.data.datasets[1].data = data.baseline_history.map(
                        b => b.stddev
                    );
                    chart.update();
                }

                // Banned IPs table
                const bannedTable = document.getElementById('banned-table');
                if (data.banned_ips.length === 0) {
                    bannedTable.innerHTML =
                        '<tr><td colspan="5">No banned IPs</td></tr>';
                } else {
                    bannedTable.innerHTML = data.banned_ips.map(b => `
                        <tr>
                            <td class="banned">${b.ip}</td>
                            <td>${b.reason}</td>
                            <td>${b.banned_at}</td>
                            <td>${b.duration}</td>
                            <td>${b.ban_count}</td>
                        </tr>
                    `).join('');
                }

                // Top IPs table
                const topTable = document.getElementById('top-ips-table');
                if (data.top_ips.length === 0) {
                    topTable.innerHTML =
                        '<tr><td colspan="2">No data yet</td></tr>';
                } else {
                    topTable.innerHTML = data.top_ips.map(t => `
                        <tr>
                            <td>${t.ip}</td>
                            <td>${t.rate.toFixed(4)}</td>
                        </tr>
                    `).join('');
                }

            } catch (e) {
                document.getElementById('status').textContent =
                    '● Disconnected — retrying...';
            }
        }

        refresh();
        setInterval(refresh, 3000);
    </script>
</body>
</html>
"""


class Dashboard:
    def __init__(self, config, detector, blocker, baseline):
        self.host = config.get("dashboard_host", "0.0.0.0")
        self.port = config.get("dashboard_port", 5000)
        self.detector = detector
        self.blocker = blocker
        self.baseline = baseline
        self.start_time = time.time()
        self.baseline_history = deque(maxlen=200)

        self.app = Flask(__name__)
        self._register_routes()

        # Record baseline every 60 seconds
        self._start_baseline_recorder()

    def _start_baseline_recorder(self):
        def record():
            while True:
                self.baseline_history.append({
                    "time": time.strftime("%H:%M"),
                    "mean": round(self.baseline.effective_mean, 4),
                    "stddev": round(self.baseline.effective_stddev, 4),
                    "hour": time.localtime().tm_hour,
                })
                time.sleep(60)

        thread = threading.Thread(
            target=record,
            daemon=True,
            name="baseline-history"
        )
        thread.start()

    def _register_routes(self):

        @self.app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @self.app.route("/api/metrics")
        def metrics():
            return jsonify(self._get_metrics())

    def _get_metrics(self):
        now = time.time()
        uptime_seconds = int(now - self.start_time)
        uptime_str = self._format_uptime(uptime_seconds)

        banned = self.blocker.get_banned_ips()
        banned_list = []
        for ip, info in banned.items():
            duration = info["duration"]
            duration_str = f"{duration}s" if duration != -1 else "permanent"
            banned_list.append({
                "ip": ip,
                "reason": info["reason"],
                "banned_at": time.strftime(
                    "%H:%M:%S",
                    time.gmtime(info["banned_at"])
                ),
                "duration": duration_str,
                "ban_count": info["ban_count"],
            })

        top_ips = [
            {"ip": ip, "rate": rate}
            for ip, rate in self.detector.get_top_ips(10)
        ]

        return {
            "global_rate":       self.detector.get_global_rate(),
            "baseline_mean":     self.baseline.effective_mean,
            "baseline_stddev":   self.baseline.effective_stddev,
            "banned_count":      len(banned),
            "banned_ips":        banned_list,
            "top_ips":           top_ips,
            "cpu_percent":       psutil.cpu_percent(),
            "memory_percent":    psutil.virtual_memory().percent,
            "uptime":            uptime_str,
            "baseline_history":  list(self.baseline_history),
        }

    def _format_uptime(self, seconds):
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs}s"

    def start(self):
        thread = threading.Thread(
            target=lambda: self.app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
            ),
            daemon=True,
            name="dashboard",
        )
        thread.start()
        print(f"[dashboard] Live at http://{self.host}:{self.port}")
