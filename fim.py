import time
import yaml
from hasher import calculate_sha256
from logger import write_fim_event

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

paths = config["paths"]
hostname = config["hostname"]

# Build initial snapshot baseline
snapshot = {}
for path in paths:
    snapshot[path] = calculate_sha256(path)

print("[*] FIM Started. Monitoring file modifications...")

try:
    while True:
        for path in paths:
            current_hash = calculate_sha256(path)
            old_hash = snapshot.get(path)

            if old_hash is None and current_hash is not None:
                write_fim_event("CREATED", path, None, current_hash, hostname, "WARNING")
                snapshot[path] = current_hash
            elif old_hash is not None and current_hash is None:
                write_fim_event("DELETED", path, old_hash, None, hostname, "CRITICAL")
                snapshot[path] = None
            elif old_hash != current_hash:
                write_fim_event("MODIFIED", path, old_hash, current_hash, hostname, "CRITICAL")
                snapshot[path] = current_hash

        time.sleep(config["poll_interval"])
except KeyboardInterrupt:
    print("\n[!] FIM Stopped.")
