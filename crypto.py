from cryptography.fernet import Fernet
import base64
import os
from pathlib import Path

def generate_key():
    """توليد مفتاح تشفير جديد"""
    return Fernet.generate_key()

def get_encryption_key():
    """الحصول على مفتاح التشفير من الإعدادات أو إنشاء مفتاح جديد"""
    key = os.environ.get('DOCUMENT_ENCRYPTION_KEY')
    if not key:
        key = generate_key()
        env_path = Path('.env')
        
        # التحقق من وجود الملف
        if not env_path.exists():
            env_path.touch()
            
        # قراءة المحتوى الحالي
        current_content = env_path.read_text() if env_path.stat().st_size > 0 else ""
        
        # التحقق من عدم وجود المفتاح مسبقاً
        if 'DOCUMENT_ENCRYPTION_KEY' not in current_content:
            with env_path.open('a') as f:
                f.write(f'\nDOCUMENT_ENCRYPTION_KEY={key.decode()}')
        
        os.environ['DOCUMENT_ENCRYPTION_KEY'] = key.decode()
    
    return key.encode() if isinstance(key, str) else key

def encrypt_data(data, key=None):
    """تشفير البيانات باستخدام مفتاح Fernet"""
    if key is None:
        key = get_encryption_key()
    if isinstance(key, str):
        key = key.encode()
    
    f = Fernet(key)
    return f.encrypt(data if isinstance(data, bytes) else data.encode())

def decrypt_data(encrypted_data, key=None):
    """فك تشفير البيانات باستخدام مفتاح Fernet"""
    if key is None:
        key = get_encryption_key()
    if isinstance(key, str):
        key = key.encode()
    
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_data)
    return decrypted 