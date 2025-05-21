from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json
import hashlib

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    is_two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))
    backup_codes = db.Column(db.Text)  # Stored as JSON string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    theme_preference = db.Column(db.String(10), default='light')
    profile_picture = db.Column(db.String(255), default='default_profile.png')  # Profile picture path
    phone = db.Column(db.String(20))  # Phone number
    bio = db.Column(db.Text)  # User bio

    def __repr__(self):
        return f'<User {self.email}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def toggle_theme(self):
        self.theme_preference = 'dark' if self.theme_preference == 'light' else 'light'
        db.session.commit()
        return self.theme_preference

    def get_backup_codes(self):
        """Get backup codes"""
        if not self.backup_codes:
            return []
        return json.loads(self.backup_codes)

    def set_backup_codes(self, codes):
        """Store backup codes"""
        self.backup_codes = json.dumps(codes)
        db.session.commit()

    def verify_backup_code(self, code):
        """Verify backup code"""
        codes = self.get_backup_codes()
        if code in codes:
            codes.remove(code)
            self.set_backup_codes(codes)
            return True
        return False

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_content = db.Column(db.LargeBinary)
    content_hash = db.Column(db.String(64))
    mime_type = db.Column(db.String(100))
    file_size = db.Column(db.Integer)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_modified = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    signature = db.Column(db.String(255))  # For digital signature
    status = db.Column(db.String(20), default='draft')  # Document status: draft, published, deleted
    version = db.Column(db.Integer, default=1)  # Document version

    def __repr__(self):
        return f'<Document {self.filename}>'

    def log_modification(self, user_id, action_type, details=None):
        """Log document modification in activity log"""
        activity = ActivityLog(
            user_id=user_id,
            action=f'document_{action_type}',
            description=f'Document {self.filename} was {action_type}. {details if details else ""}',
            ip_address=None  # Will be filled in the route
        )
        db.session.add(activity)
        db.session.commit()

    def update_document(self, user_id, new_content=None, new_filename=None, new_status=None):
        """Update document and log changes"""
        changes = []
        
        if new_content is not None:
            self.encrypted_content = new_content
            self.content_hash = hashlib.sha256(new_content).hexdigest()
            changes.append("Content updated")
            
        if new_filename is not None:
            old_filename = self.filename
            self.filename = new_filename
            changes.append(f"Filename changed from '{old_filename}' to '{new_filename}'")
            
        if new_status is not None:
            old_status = self.status
            self.status = new_status
            changes.append(f"Status changed from '{old_status}' to '{new_status}'")
            
        self.last_modified = datetime.utcnow()
        self.version += 1
        
        # Log modification in activity log with detailed information
        if changes:
            user = User.query.get(user_id)
            user_role = user.role if user else 'unknown'
            self.log_modification(
                user_id,
                'update',
                f"User ({user_role}) made changes: {', '.join(changes)}"
            )
        
        db.session.commit()

class DocumentVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id', ondelete='CASCADE'))
    version_number = db.Column(db.Integer, nullable=False)
    encrypted_content = db.Column(db.LargeBinary)
    content_hash = db.Column(db.String(64))
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    signature = db.Column(db.String(255))  # For digital signature

    def __repr__(self):
        return f'<DocumentVersion {self.document_id} v{self.version_number}>'

class DocumentShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id', ondelete='CASCADE'))
    shared_with = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    permission_level = db.Column(db.String(20), default='read')
    shared_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<DocumentShare {self.id}>'

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'))
    action = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ActivityLog {self.id}>'

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Create tables
def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all() 
