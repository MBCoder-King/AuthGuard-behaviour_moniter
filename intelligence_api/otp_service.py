"""
AuthGuard Enterprise - OTP Service
Email-based one-time password system for account recovery
"""

import os
import smtplib
import random
import logging
from datetime import datetime, timedelta
from email.message import EmailMessage
from typing import Optional, Dict
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_db import get_cache

logger = logging.getLogger(__name__)


class OTPService:
    """
    One-Time Password service for secure account recovery
    Uses Redis for temporary storage with TTL
    """
    
    def __init__(self):
        self.cache = get_cache()
        self.smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.smtp_user = os.getenv('SMTP_USER')
        self.smtp_pass = os.getenv('SMTP_PASS')
        self.from_name = os.getenv('EMAIL_FROM_NAME', 'AuthGuard Security')
        self.otp_length = 6
        self.otp_ttl = 600  # 10 minutes
        self.max_attempts = 3
    
    def generate_otp(self) -> str:
        """Generate a random 6-digit OTP"""
        return str(random.randint(100000, 999999))
    
    def send_otp(self, email: str, user_uid: str) -> bool:
        """
        Generate and send OTP to user's email
        
        Args:
            email: User's email address
            user_uid: User's unique identifier
        
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # Generate OTP
            otp_code = self.generate_otp()
            
            # Store in cache with TTL
            cache_key = f"otp:{user_uid}"
            otp_data = {
                'code': otp_code,
                'email': email,
                'attempts': 0,
                'created_at': datetime.utcnow().isoformat()
            }
            
            self.cache.set(cache_key, otp_data, ttl=self.otp_ttl)
            
            # Send email
            success = self._send_email(email, otp_code, user_uid)
            
            if success:
                logger.info(f"OTP sent to {email} for user {user_uid}")
            else:
                logger.error(f"Failed to send OTP to {email}")
            
            return success
            
        except Exception as e:
            logger.error(f"OTP generation error: {e}", exc_info=True)
            return False
    
    def verify_otp(self, user_uid: str, provided_code: str) -> bool:
        """
        Verify the OTP code
        
        Args:
            user_uid: User's unique identifier
            provided_code: OTP code provided by user
        
        Returns:
            True if valid, False otherwise
        """
        try:
            cache_key = f"otp:{user_uid}"
            otp_data = self.cache.get(cache_key)
            
            if not otp_data:
                logger.warning(f"OTP not found or expired for {user_uid}")
                return False
            
            # Check attempts
            if otp_data['attempts'] >= self.max_attempts:
                logger.warning(f"Max OTP attempts exceeded for {user_uid}")
                self.cache.delete(cache_key)
                return False
            
            # Verify code
            if otp_data['code'] == provided_code:
                # Valid code - delete from cache
                self.cache.delete(cache_key)
                logger.info(f"OTP verified successfully for {user_uid}")
                return True
            else:
                # Invalid code - increment attempts
                otp_data['attempts'] += 1
                self.cache.set(cache_key, otp_data, ttl=self.otp_ttl)
                logger.warning(f"Invalid OTP attempt for {user_uid}")
                return False
                
        except Exception as e:
            logger.error(f"OTP verification error: {e}", exc_info=True)
            return False
    
    def _send_email(self, to_email: str, otp_code: str, user_uid: str) -> bool:
        """
        Send OTP email via SMTP
        
        Args:
            to_email: Recipient email address
            otp_code: OTP code to send
            user_uid: User identifier for logging
        
        Returns:
            True if sent successfully
        """
        if not self.smtp_user or not self.smtp_pass:
            logger.error("SMTP credentials not configured")
            return False
        
        try:
            # Create email message
            msg = EmailMessage()
            msg['Subject'] = 'AuthGuard Security - Account Recovery Code'
            msg['From'] = f'{self.from_name} <{self.smtp_user}>'
            msg['To'] = to_email
            
            # HTML email body
            html_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        background-color: #f4f4f4;
                        margin: 0;
                        padding: 0;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 40px auto;
                        background-color: #ffffff;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        overflow: hidden;
                    }}
                    .header {{
                        background: linear-gradient(135deg, #38bdf8 0%, #0284c7 100%);
                        color: white;
                        padding: 30px;
                        text-align: center;
                    }}
                    .header h1 {{
                        margin: 0;
                        font-size: 28px;
                    }}
                    .content {{
                        padding: 40px 30px;
                    }}
                    .alert {{
                        background-color: #fee2e2;
                        border-left: 4px solid #ef4444;
                        padding: 15px;
                        margin: 20px 0;
                        border-radius: 4px;
                    }}
                    .alert h3 {{
                        margin: 0 0 10px 0;
                        color: #991b1b;
                    }}
                    .otp-box {{
                        background-color: #f0f9ff;
                        border: 2px dashed #38bdf8;
                        border-radius: 8px;
                        padding: 25px;
                        text-align: center;
                        margin: 30px 0;
                    }}
                    .otp-code {{
                        font-size: 42px;
                        font-weight: bold;
                        color: #0284c7;
                        letter-spacing: 8px;
                        font-family: 'Courier New', monospace;
                    }}
                    .info {{
                        color: #64748b;
                        font-size: 14px;
                        line-height: 1.6;
                    }}
                    .footer {{
                        background-color: #f8fafc;
                        padding: 20px;
                        text-align: center;
                        color: #64748b;
                        font-size: 12px;
                    }}
                    .button {{
                        display: inline-block;
                        padding: 12px 30px;
                        background-color: #38bdf8;
                        color: white;
                        text-decoration: none;
                        border-radius: 6px;
                        margin: 20px 0;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🛡️ AuthGuard Security</h1>
                    </div>
                    
                    <div class="content">
                        <div class="alert">
                            <h3>⚠️ SECURITY ALERT</h3>
                            <p>Your account was temporarily locked due to anomalous behavioral patterns detected by our AI security system.</p>
                        </div>
                        
                        <p>To unlock your account and restore access, please use the following verification code:</p>
                        
                        <div class="otp-box">
                            <div class="otp-code">{otp_code}</div>
                            <p style="margin: 10px 0 0 0; color: #64748b;">This code expires in 10 minutes</p>
                        </div>
                        
                        <div class="info">
                            <p><strong>What happened?</strong></p>
                            <p>Our continuous authentication system detected unusual activity that doesn't match your normal behavior patterns. This could include:</p>
                            <ul>
                                <li>Different typing rhythm or speed</li>
                                <li>Unusual mouse movement patterns</li>
                                <li>Login from a new device or location</li>
                                <li>Automated bot-like behavior</li>
                            </ul>
                            
                            <p><strong>What should I do?</strong></p>
                            <ol>
                                <li>Enter the code above in the unlock screen</li>
                                <li>If you didn't trigger this alert, change your password immediately</li>
                                <li>Contact our support team if you need assistance</li>
                            </ol>
                        </div>
                        
                        <p class="info">
                            <strong>Didn't request this code?</strong><br>
                            If you did not attempt to access your account, please contact our security team immediately at security@authguard.io
                        </p>
                    </div>
                    
                    <div class="footer">
                        <p>
                            This email was sent from AuthGuard Security System<br>
                            User ID: {user_uid}<br>
                            Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
                        </p>
                        <p>© 2024 AuthGuard. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Set HTML content
            msg.set_content("Please enable HTML to view this email.")
            msg.add_alternative(html_body, subtype='html')
            
            # Send via SMTP
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP authentication failed - check credentials")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return False
        except Exception as e:
            logger.error(f"Email send error: {e}", exc_info=True)
            return False
    
    def resend_otp(self, user_uid: str) -> bool:
        """
        Resend OTP if previous one expired
        
        Args:
            user_uid: User's unique identifier
        
        Returns:
            True if resent successfully
        """
        cache_key = f"otp:{user_uid}"
        otp_data = self.cache.get(cache_key)
        
        if not otp_data:
            logger.warning(f"Cannot resend OTP - no active request for {user_uid}")
            return False
        
        # Resend to same email
        return self.send_otp(otp_data['email'], user_uid)


# Singleton instance
_otp_service_instance = None

def get_otp_service() -> OTPService:
    """Get OTP service singleton instance"""
    global _otp_service_instance
    if not _otp_service_instance:
        _otp_service_instance = OTPService()
    return _otp_service_instance


if __name__ == "__main__":
    # Test OTP service
    print("Testing OTP Service...")
    
    service = OTPService()
    test_email = "test@example.com"
    test_uid = "test_user_123"
    
    print(f"Sending OTP to {test_email}...")
    # success = service.send_otp(test_email, test_uid)
    # print(f"Send result: {success}")
    
    # In production, you'd get this from user input
    # test_code = input("Enter OTP code: ")
    # valid = service.verify_otp(test_uid, test_code)
    # print(f"Verification result: {valid}")