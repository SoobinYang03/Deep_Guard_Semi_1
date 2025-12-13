import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MIMEMultipart
from app.config import SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, ADMIN_EMAILS
from app.models import Leak

async def send_leak_alert(leak: Leak):
    """Leak 저장 후 관리자 계정 감지 시 이메일 알림"""
    if "admin" not in leak.get("username", "").lower() and leak.get("severity") != "critical":
        return  # 관리자/심각도 필터
    
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['Subject'] = f"🚨 새 유출 감지: {leak['site_domain']}"
    
    body = f"""
새 유출 레코드가 감지되었습니다:
- 도메인: {leak['site_domain']}
- 사용자: {leak['username']}
- 심각도: {leak['severity']}
- 날짜: {leak['leak_date']}
링크: http://localhost:8000/leaks/{str(leak['_id'])}
    """
    msg.attach(MimeText(body, 'plain', 'utf-8'))
    
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        for admin_email in ADMIN_EMAILS:
            server.sendmail(SMTP_USER, admin_email.strip(), msg.as_string())
        server.quit()
        print(f"✅ 이메일 알림 전송: {leak['site_domain']}")
    except Exception as e:
        print(f"❌ 이메일 전송 실패: {e}")
