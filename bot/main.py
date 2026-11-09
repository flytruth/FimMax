#!/usr/bin/env python3
import sys
import json
import requests

# Hardcoded Chat ID (or pass via options in ossec.conf)
CHAT_ID = "YOUR_CHAT_ID_HERE"

def send_telegram_alert(alert_file, api_key):
    try:
        with open(alert_file, 'r') as f:
            alert = json.load(f)
    except Exception as e:
        sys.exit(1)

    # Extract alert metadata
    rule_id = alert.get("rule", {}).get("id", "N/A")
    rule_level = alert.get("rule", {}).get("level", "N/A")
    description = alert.get("rule", {}).get("description", "No description")
    agent_name = alert.get("agent", {}).get("name", "Manager/Localhost")
    agent_id = alert.get("agent", {}).get("id", "000")
    full_log = alert.get("full_log", "N/A")

    # Format Markdown message
    message = (
        f"🚨 *Wazuh Alert*\n\n"
        f"🔹 *Rule ID:* `{rule_id}` (Level {rule_level})\n"
        f"🔹 *Description:* {description}\n"
        f"🔹 *Agent:* {agent_name} (`ID: {agent_id}`)\n"
        f"```\n{full_log[:500]}\n```"  # Truncates log if too long
    )

    # Telegram API Endpoint
    url = f"https://api.telegram.org/bot{api_key}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        alert_file_path = sys.argv[1]
        api_key = sys.argv[2]
        send_telegram_alert(alert_file_path, api_key)
