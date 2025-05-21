class User(UserMixin, db.Model):
    """نموذج المستخدم"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_update = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    # إعدادات المصادقة الثنائية
    two_fa_enabled = db.Column(db.Boolean, default=False)
    two_fa_secret = db.Column(db.String(32))
    
    # إعدادات الإشعارات
    notification_settings = db.Column(db.JSON, default=lambda: {
        'email_login': True,
        'email_upload': True,
        'email_share': True,
        'system_updates': True,
        'security_alerts': True
    })
    
    # إعدادات التخصيص
    theme = db.Column(db.String(10), default='light')
    language = db.Column(db.String(5), default='ar')
    timezone = db.Column(db.String(10), default='UTC+3')
    
    # إعدادات التخزين
    auto_cleanup = db.Column(db.Boolean, default=True)
    cleanup_period = db.Column(db.Integer, default=30)  # بالأيام
    storage_used = db.Column(db.BigInteger, default=0)  # بالبايت
    storage_limit = db.Column(db.BigInteger, default=10737418240)  # 10 GB بالبايت 