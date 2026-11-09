import json
from datetime import datetime, timezone

def write_fim_event(event_type, file_path, sha_before, sha_after, hostname, severity="WARNING"):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event_type": event_type,
        "file_path": file_path,
        "sha256_before": sha_before,
        "sha256_after": sha_after,
        "hostname": hostname,
        "severity": severity
    }

    # Write to local JSON log
    with open("fim_events.log", "a") as f:
        f.write(json.dumps(event) + "\n")

    return event
