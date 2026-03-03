# SMTP notification sender
# Wazuh Inc.
# Nicolás Curioni <nicolas.curioni@wazuh.com>
import json
import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# === SMTP CONFIGURATION ===
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "<EMAIL>"
SMTP_PASS = "<APP PASSWORD>" 
DESTINATARIO = "<RECEIVER EMAIL>"

LOG_PATH = "/var/log/health-checker.json"
HOSTNAME = socket.gethostname()

def send_email_notification():
    try:
        with open(LOG_PATH, 'r') as f:
            lines = f.readlines()
            if not lines: return
            data = json.loads(lines[-1].strip())

        all_checks = data.get('checks', {})
        issues = []
        for check_id, details in all_checks.items():
            if details.get('notify') is True:
                msg = details.get('details') or details.get('issues') or "Revisar logs"
                if isinstance(msg, list): msg = "<br>".join([f"• {m}" for m in msg])
                
                issues.append({
                    "name": check_id.replace('_', ' ').title(),
                    "status": details.get('status', 'WARNING').upper(),
                    "message": msg
                })

        if not issues:
            print("Correo: No hay alertas para enviar.")
            return

        subject = f"⚠️ ALERT: Wazuh Health Check - {HOSTNAME}"
        
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <h2 style="color: #d9534f;">Wazuh Alerts report</h2>
            <p>Some issues were detected at server: <strong>{HOSTNAME}</strong></p>
            <table border="1" cellpadding="10" cellspacing="0" style="border-collapse: collapse; width: 100%;">
                <tr style="background-color: #f8f9fa;">
                    <th>Component</th>
                    <th>State</th>
                    <th>Details</th>
                </tr>
        """
        for issue in issues:
            color = "#d9534f" if issue['status'] == "ERROR" else "#f0ad4e"
            html += f"""
                <tr>
                    <td><strong>{issue['name']}</strong></td>
                    <td style="color: white; background-color: {color}; text-align: center;">{issue['status']}</td>
                    <td>{issue['message']}</td>
                </tr>
            """
        html += "</table><br><p>Please contact Wazuh Support Team at support@wazuh.com</p></body></html>"

        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = DESTINATARIO
        msg['Subject'] = subject
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Seguridad
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
            
        print("✅ Email successfully sent.")

    except Exception as e:
        print(f"❌ Error sending email: {e}")

if __name__ == "__main__":
    send_email_notification()
