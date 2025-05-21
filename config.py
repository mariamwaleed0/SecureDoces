import os
from datetime import timedelta

class Config:
    # Flask configuration
    SECRET_KEY = 'your-secret-key-here'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # Database configuration for XAMPP
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://root:@localhost:3306/securedocs?charset=utf8mb4&collation=utf8mb4_general_ci'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File upload configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png'}
    
    # Security configuration
    SESSION_COOKIE_SECURE = True  # Enabled for HTTPS
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = True  # Enabled for HTTPS
    REMEMBER_COOKIE_HTTPONLY = True
    
    # SSL/TLS Configuration
    SSL_CERTIFICATE = 'cert.pem'
    SSL_PRIVATE_KEY = 'key.pem'
    
    # Application configuration
    APP_NAME = 'Document Management System'
    APP_VERSION = '1.0.0'
    DEBUG = True
    
    # Storage configuration
    DEFAULT_STORAGE_LIMIT = 1024 * 1024 * 1024  # 1GB default storage limit
    
    # Theme configuration
    DEFAULT_THEME = 'light'
    AVAILABLE_THEMES = ['light', 'dark']
    
    # Security headers
    SECURITY_HEADERS = {
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' https://cdn.jsdelivr.net;",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
    
    # Theme configuration
    THEME_CONFIG = {
        'light': {
            'primary': '#4361ee',
            'secondary': '#3f37c9',
            'accent': '#4895ef',
            'background': '#f8f9fa',
            'text': '#333333',
            'card': '#ffffff'
        },
        'dark': {
            'primary': '#4895ef',
            'secondary': '#4361ee',
            'accent': '#3f37c9',
            'background': '#1a1a1a',
            'text': '#ffffff',
            'card': '#2d2d2d'
        }
    }
