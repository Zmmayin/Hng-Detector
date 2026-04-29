import json
import time
import os

IGNORED_IPS = {
    "127.0.0.1",
    "::1",
}

IGNORED_PATHS = {
    "/api/metrics",
    "/favicon.ico",
}


def tail_log(log_path):
    while not os.path.exists(log_path):
        print(f"[monitor] Waiting for log file: {log_path}")
        time.sleep(2)

    print(f"[monitor] Tailing log file: {log_path}")

    current_inode = os.stat(log_path).st_ino
    f = open(log_path, "r")
    f.seek(0, 2)
    print(f"[monitor] Started at end of file, inode={current_inode}")

    while True:
        try:
            line = f.readline()

            if not line:
                time.sleep(0.1)

                # Check if file has been rotated
                try:
                    new_inode = os.stat(log_path).st_ino
                    if new_inode != current_inode:
                        print(f"[monitor] Log rotated — reopening")
                        f.close()
                        f = open(log_path, "r")
                        current_inode = new_inode
                except FileNotFoundError:
                    time.sleep(1)
                continue

            line = line.strip()
            if not line:
                continue

            parsed = parse_line(line)
            if parsed:
                print(f"[monitor] Got request from {parsed['source_ip']} {parsed['path']}")
                yield parsed

        except Exception as e:
            print(f"[monitor] Error: {e}")
            time.sleep(1)


def parse_line(line):
    try:
        data = json.loads(line)
        ip = data.get("source_ip", "")
        path = data.get("path", "")

        # Skip internal Docker IPs
        if ip in IGNORED_IPS or ip.startswith("172."):
            return None

        # Skip internal paths
        if path in IGNORED_PATHS or path.startswith("/api/"):
            return None

        return {
            "source_ip":     ip,
            "timestamp":     data.get("timestamp", ""),
            "method":        data.get("method", ""),
            "path":          path,
            "status":        int(data.get("status", 0)),
            "response_size": int(data.get("response_size", 0)),
        }

    except (json.JSONDecodeError, ValueError):
        return None
