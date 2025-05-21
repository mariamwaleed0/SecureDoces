import pyotp
import qrcode
import base64
from io import BytesIO
import secrets
import string

class TwoFactorAuth:
    @staticmethod
    def generate_secret():
        """إنشاء مفتاح سري جديد للمصادقة الثنائية"""
        return pyotp.random_base32()

    @staticmethod
    def generate_totp_uri(secret, email):
        """إنشاء رابط TOTP للمصادقة الثنائية"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(email, issuer_name="SecureDocs")

    @staticmethod
    def verify_totp(secret, token):
        """التحقق من رمز المصادقة الثنائية"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token)

    @staticmethod
    def generate_qr_code(uri):
        """إنشاء رمز QR للمصادقة الثنائية"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode()

    @staticmethod
    def generate_backup_codes(count=8):
        """إنشاء رموز نسخ احتياطية"""
        codes = []
        for _ in range(count):
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(10))
            codes.append(code)
        return codes
