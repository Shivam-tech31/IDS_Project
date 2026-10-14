"""
Email and SMS alert notifications for critical IDS events.
Set NOTIFICATIONS_ENABLED=true in .env to activate.
"""

import os
import smtplib
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import httpx

NOTIFICATIONS_ENABLED = os.getenv("NOTIFICATIONS_ENABLED", "false").lower() == "true"
ALERT_EMAIL           = os.getenv("ALERT_EMAIL", "")
ALERT_EMAIL_PASSWORD  = os.getenv("ALERT_EMAIL_PASSWORD", "")
ALERT_RECEIVER        = os.getenv("ALERT_RECEIVER", "")
FAST2SMS_KEY          = os.getenv("FAST2SMS_KEY", "")
SMS_RECEIVER          = os.getenv("SMS_RECEIVER", "")


def send_email_alert(event: dict):
    """Send HTML email alert via Gmail SMTP SSL."""
    if not NOTIFICATIONS_ENABLED or not ALERT_EMAIL:
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 IDS Alert — {event.get('attack_type')} detected"
        msg["From"]    = ALERT_EMAIL
        msg["To"]      = ALERT_RECEIVER

        html = f"""
        <html><body style="font-family:Arial,sans-serif;background:#0a0e1a;color:#e2e8f0;padding:20px">
        <h2 style="color:#f87171">🚨 Intrusion Detected</h2>
        <table style="border-collapse:collapse;width:100%">
          <tr><td style="padding:8px;color:#94a3b8">Attack Type</td><td style="padding:8px;color:#f87171"><b>{event.get('attack_type')}</b></td></tr>
          <tr><td style="padding:8px;color:#94a3b8">Severity</td><td style="padding:8px">{event.get('severity','').upper()}</td></tr>
          <tr><td style="padding:8px;color:#94a3b8">Source IP</td><td style="padding:8px;font-family:monospace">{event.get('src_ip')}</td></tr>
          <tr><td style="padding:8px;color:#94a3b8">Destination IP</td><td style="padding:8px;font-family:monospace">{event.get('dst_ip')}</td></tr>
          <tr><td style="padding:8px;color:#94a3b8">Confidence</td><td style="padding:8px">{event.get('confidence')}%</td></tr>
          <tr><td style="padding:8px;color:#94a3b8">Timestamp</td><td style="padding:8px">{event.get('timestamp')}</td></tr>
        </table>
        <p style="color:#64748b;font-size:12px;margin-top:20px">IDS — Real-Time Intrusion Detection System</p>
        </body></html>
        """
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(ALERT_EMAIL, ALERT_EMAIL_PASSWORD)
            server.sendmail(ALERT_EMAIL, ALERT_RECEIVER, msg.as_string())
    except Exception as e:
        print(f"Email alert error: {e}")


async def send_sms_alert(event: dict):
    """Send SMS alert via Fast2SMS (free Indian SMS API)."""
    if not NOTIFICATIONS_ENABLED or not FAST2SMS_KEY:
        return
    try:
        msg = (f"IDS ALERT: {event.get('attack_type')} attack from "
               f"{event.get('src_ip')} | Severity: {event.get('severity','').upper()} "
               f"| Confidence: {event.get('confidence')}%")
        async with httpx.AsyncClient() as client:
            await client.post(
                "https://www.fast2sms.com/dev/bulkV2",
                headers={"authorization": FAST2SMS_KEY},
                data={
                    "variables_values": msg,
                    "route":            "q",
                    "numbers":          SMS_RECEIVER,
                },
                timeout=5.0,
            )
    except Exception as e:
        print(f"SMS alert error: {e}")


async def send_critical_alert(event: dict):
    """Called for critical severity events — sends both email and SMS."""
    if not NOTIFICATIONS_ENABLED:
        return
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, send_email_alert, event)
    await send_sms_alert(event)
