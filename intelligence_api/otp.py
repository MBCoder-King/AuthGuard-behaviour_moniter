import smtplib
import random
import os
from email.message import EmailMessage

SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASS = os.getenv('SMTP_PASS')

def generate_otp():
    return str(random.randint(100000, 999999))

def send_recovery_email(to_email, otp_code):
    try:
        msg = EmailMessage()
        msg.set_content(f"""
        SECURITY ALERT
        
        Your account was temporarily locked due to anomalous behavioral patterns.
        
        Your Unlock Code is: {otp_code}
        
        If this was not you, please contact support immediately.
        """)
        
        msg['Subject'] = 'AuthGuard Security Unlock Code'
        msg['From'] = SMTP_USER
        msg['To'] = to_email

        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"SMTP Error: {e}")
        return False