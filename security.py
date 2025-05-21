import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
import hashlib
import hmac
import base64
import qrcode
import pyotp
from werkzeug.security import generate_password_hash, check_password_hash

class SecurityUtils:
    @staticmethod
    def is_strong_password(password):
        """
        التحقق من قوة كلمة المرور
        يجب أن تحتوي على:
        - 8 أحرف على الأقل
        - حرف كبير واحد على الأقل
        - حرف صغير واحد على الأقل
        - رقم واحد على الأقل
        - رمز خاص واحد على الأقل
        """
        if len(password) < 8:
            return False
            
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # التحقق من أن كلمة المرور ليست من الكلمات الشائعة
        common_passwords = ['password', '123456', 'qwerty', 'letmein', 'admin']
        if password.lower() in common_passwords:
            return False
            
        return all([has_upper, has_lower, has_digit, has_special])

    @staticmethod
    def generate_totp_secret():
        """توليد مفتاح سري للمصادقة الثنائية"""
        return pyotp.random_base32()

    @staticmethod
    def generate_totp_uri(secret: str, email: str, issuer: str = "SecureApp"):
        """Generate TOTP URI for two-factor authentication"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(email, issuer_name=issuer)

    @staticmethod
    def verify_totp(secret, token):
        """التحقق من رمز المصادقة الثنائية"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token)

    @staticmethod
    def generate_qr_code(data: str, filename: str):
        """Generate QR code"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(filename)

    @staticmethod
    def encrypt_file(file_data: bytes, key: bytes) -> bytes:
        """Encrypt file using AES"""
        f = Fernet(key)
        return f.encrypt(file_data)

    @staticmethod
    def decrypt_file(encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt file"""
        f = Fernet(key)
        return f.decrypt(encrypted_data)

    @staticmethod
    def calculate_file_hash(file_data: bytes) -> str:
        """Calculate SHA-256 hash of file"""
        return hashlib.sha256(file_data).hexdigest()

    @staticmethod
    def calculate_hmac(file_data: bytes, key: bytes) -> str:
        """Calculate HMAC for file integrity verification"""
        h = hmac.new(key, file_data, hashlib.sha256)
        return h.hexdigest()

    @staticmethod
    def generate_key_pair():
        """Generate key pair for digital signature"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def sign_file(file_data: bytes, private_key) -> str:
        """Digitally sign file"""
        signature = private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(file_data: bytes, signature: str, public_key) -> bool:
        """Verify digital signature"""
        try:
            signature_bytes = base64.b64decode(signature.encode('utf-8'))
            public_key.verify(
                signature_bytes,
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using Werkzeug's secure hashing"""
        return generate_password_hash(password)

    @staticmethod
    def verify_password(password_hash: str, password: str) -> bool:
        """Verify password against hash using Werkzeug's secure hashing"""
        return check_password_hash(password_hash, password) 