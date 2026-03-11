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

def _format_agents_msg(details: dict) -> str:
    """Build a bullet-point agent summary from the agents check payload."""
    total       = details.get('total', 0)
    active      = details.get('active', 0)
    active_pct  = details.get('active_pct', 0.0)
    disc        = details.get('disconnected', 0)
    disc_pct    = details.get('disconnected_pct', 0.0)
    pending     = details.get('pending', 0)
    pending_pct = details.get('pending_pct', 0.0)
    never       = details.get('never_connected', 0)
    never_pct   = details.get('never_connected_pct', 0.0)
    return (
        f"• Total: {total}\n"
        f"• Active: {active} ({active_pct}%)\n"
        f"• Disconnected: {disc} ({disc_pct}%)\n"
        f"• Pending: {pending} ({pending_pct}%)\n"
        f"• Never connected: {never} ({never_pct}%)"
    )


def send_notifications():
    try:
        # 1. Leer solo la última línea del log
        with open(LOG_PATH, 'r') as f:
            lines = f.readlines()
            if not lines:
                print("Empty log file")
                return
            last_line = lines[-1].strip()
            
        # 2. Parsear el JSON de esa línea
        data = json.loads(last_line)
        all_checks = data.get('checks', {})
        issues = []

        # 3. Analizar los checks
        for check_id, details in all_checks.items():
            # El check de agentes siempre se incluye si tiene datos
            if check_id == 'agents' and details.get('total') is not None:
                msg = _format_agents_msg(details)
                issues.append({
                    "name": "Agent Summary",
                    "status": details.get('status', 'OK').upper(),
                    "message": msg
                })
                continue

            # El resto: solo si requieren notificación
            if details.get('notify') is not True:
                continue

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

        # 4. Construir el payload para Slack
        slack_payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 Wazuh Health Alert: {HOSTNAME}"}
                },
                {"type": "divider"}
            ]
        }

        # Primero los warnings/errors, luego el resumen de agentes al final
        alerts   = [i for i in issues if i['status'] != 'OK']
        info     = [i for i in issues if i['status'] == 'OK']
        ordered  = sorted(alerts, key=lambda x: x['status']) + info

        for issue in ordered:
            if issue['status'] == 'ERROR':
                emoji = "🔴"
            elif issue['status'] == 'WARNING':
                emoji = "⚠️"
            else:
                emoji = "✅"

            slack_payload["blocks"].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} *{issue['name']}* | `{issue['status']}`\n{issue['message']}"
                }
            })

        # 5. Enviar a Slack
        resp = requests.post(SLACK_WEBHOOK_URL, json=slack_payload, timeout=10)

        # A n8n (Payload completo para lógica avanzada)
        # requests.post(N8N_WEBHOOK_URL, json={
        #     "hostname": HOSTNAME,
        #     "status": "issues_detected",
        #     "report": data
        # }, timeout=10)

        print(f"✅ Notification sent: {len(alerts)} alert(s) found.")

    except Exception as e:
        print(f"❌ Error in the process: {e}")


if __name__ == "__main__":
    send_notifications()
