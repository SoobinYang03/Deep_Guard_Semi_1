# app/notifications/email.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config import SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, ADMIN_EMAILS

async def send_leak_alert(domain: str, masked_email: str, risk_level: str):
    subject = f"[DeepGuard] 새 유출 감지: {domain}"
    body = f"""
다음 이메일 유출이 탐지되었습니다.

- 마스킹 이메일: {masked_email}
- 도메인: {domain}
- 위험도: {risk_level}
"""

    msg = MIMEMultipart()
    msg["From"] = SMTP_USER
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(SMTP_USER, SMTP_PASSWORD)
    for admin_email in ADMIN_EMAILS:
        admin_email = admin_email.strip()
        if not admin_email:
            continue
        msg["To"] = admin_email
        server.sendmail(SMTP_USER, admin_email, msg.as_string())
    server.quit()

