# Slack notification sender
# Wazuh Inc. 
# Nicolás Curioni <nicolas.curioni@wazuh.com>
import json
import requests
import socket
import sys

# === CONFIGURATION ===
SLACK_WEBHOOK_URL = "<https://hooks.slack.com/services/......>"
LOG_PATH = "/var/log/health-checker.json"
HOSTNAME = socket.gethostname()

def send_notifications():
    try:
        # Reading last log line 
        with open(LOG_PATH, 'r') as f:
            lines = f.readlines()
            if not lines:
                print("Empty log file")
                return
            last_line = lines[-1].strip()
            
        # JSON parsing
        data = json.loads(last_line)
        all_checks = data.get('checks', {})
        issues = []

        # Check analysis
        for check_id, details in all_checks.items():
            if details.get('notify') is True:
                msg = details.get('details') or details.get('issues') or "Review configuration"
                if isinstance(msg, list):
                    msg = "\n".join([f"• {m}" for m in msg])
                issues.append({
                    "name": check_id.replace('_', ' ').title(),
                    "status": details.get('status', 'WARNING').upper(),
                    "message": msg
                })

        if not issues:
            print("No problems that need attention were found.")
            return

        # Slack payload
        slack_payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 Wazuh Health Alert: {HOSTNAME}"}
                },
                {"type": "divider"}
            ]
        }

        for issue in sorted(issues, key=lambda x: x['status']):
            emoji = "🔴" if issue['status'] == "ERROR" else "⚠️"
            slack_payload["blocks"].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn", 
                    "text": f"{emoji} *{issue['name']}* | `{issue['status']}`\n{issue['message']}"
                }
            })

        requests.post(SLACK_WEBHOOK_URL, json=slack_payload, timeout=10)
        

        print(f"✅ Notification sent: {len(issues)} alerts were found.")

    except Exception as e:
        print(f"❌ Error in the process: {e}")

if __name__ == "__main__":
    send_notifications()
