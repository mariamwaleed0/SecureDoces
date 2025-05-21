from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify, send_from_directory
from flask_login import LoginManager, current_user, login_required, login_user
from flask_migrate import Migrate
from models import db, User, Document, init_db
from controllers.auth import auth, oauth
from controllers.documents import documents
from controllers.admin import admin
import os
from datetime import datetime
import humanize
from utils.two_factor import TwoFactorAuth
from werkzeug.security import check_password_hash
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import uuid

load_dotenv()

def create_default_admin():
    """Create default admin account if it doesn't exist"""
    admin = User.query.filter_by(email='admin@securedocs.com').first()
    if not admin:
        admin = User(
            email='admin@securedocs.com',
            name='System Administrator',
            role='admin',
            is_active=True
        )
        admin.set_password('Admin@123')
        db.session.add(admin)
        db.session.commit()
        print('Default admin account created')

def create_app():
    app = Flask(__name__)
    
    # Configure the application
    app.config.from_object('config.Config')
    
    # Initialize database
    db.init_app(app)
    
    # Initialize Flask-Migrate
    migrate = Migrate(app, db)
    
    # Initialize OAuth
    oauth.init_app(app)
    
    # Initialize login manager
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Register Blueprints
    app.register_blueprint(auth, url_prefix='/auth')
    app.register_blueprint(documents, url_prefix='/documents')
    app.register_blueprint(admin, url_prefix='/admin')
    
    # Create necessary directories
    os.makedirs('static/qr', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('static/profile_pictures', exist_ok=True)
    
    # Add profile_picture column if it doesn't exist
    with app.app_context():
        try:
            db.engine.execute('ALTER TABLE user ADD COLUMN profile_picture VARCHAR(255) DEFAULT "default_profile.png"')
        except Exception as e:
            # Column might already exist, ignore the error
            pass
    
    # Home page
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('home'))
        return render_template('index.html')

    # Home page after login
    @app.route('/home')
    @login_required
    def home():
        # Calculate statistics
        user_docs = Document.query.filter_by(uploaded_by=current_user.id).all()
        document_count = len(user_docs)
        
        # Calculate storage used
        total_size = sum(doc.file_size for doc in user_docs if doc.file_size)
        storage_used = humanize.naturalsize(total_size, binary=True)
        
        # Latest activity
        latest_doc = Document.query.filter_by(uploaded_by=current_user.id).order_by(Document.upload_date.desc()).first()
        last_activity = humanize.naturaltime(latest_doc.upload_date) if latest_doc else "No recent activity"
        
        return render_template('home.html',
                             document_count=document_count,
                             storage_used=storage_used,
                             last_activity=last_activity)

    @app.route('/verify-2fa', methods=['GET', 'POST'])
    def verify_2fa():
        if 'user_id' not in session:
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        if not user or not user.is_two_factor_enabled:
            return redirect(url_for('login'))

        if request.method == 'POST':
            token = request.form.get('token')
            if TwoFactorAuth.verify_totp(user.two_factor_secret, token):
                login_user(user)
                session.pop('user_id', None)
                return redirect(url_for('index'))
            flash('Invalid verification code. Please try again.', 'error')

        return render_template('verify_2fa.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))

        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()

            if user and user.check_password(password):
                if user.is_two_factor_enabled:
                    session['user_id'] = user.id
                    return redirect(url_for('verify_2fa'))
                login_user(user)
                return redirect(url_for('index'))

            flash('Invalid email or password', 'error')
        return render_template('login.html')

    @app.route('/toggle-theme', methods=['POST'])
    @login_required
    def toggle_theme():
        new_theme = current_user.toggle_theme()
        return jsonify({'theme': new_theme})
    
    @app.context_processor
    def inject_now():
        return {'now': datetime.now()}
    
    @app.route('/profile/upload', methods=['POST'])
    @login_required
    def upload_profile_picture():
        if 'profile_picture' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('home'))
        
        file = request.files['profile_picture']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('home'))
        
        if file:
            # Create profile pictures directory if it doesn't exist
            profile_dir = os.path.join('static', 'profile_pictures')
            os.makedirs(profile_dir, exist_ok=True)
            
            # Generate unique filename
            filename = secure_filename(file.filename)
            ext = filename.rsplit('.', 1)[1].lower()
            new_filename = f"{uuid.uuid4()}.{ext}"
            
            # Save the file
            file_path = os.path.join(profile_dir, new_filename)
            file.save(file_path)
            
            # Update user's profile picture
            current_user.profile_picture = new_filename
            db.session.commit()
            
            flash('Profile picture updated successfully', 'success')
        return redirect(url_for('home'))

    @app.route('/profile/picture/<filename>')
    def profile_picture(filename):
        return send_from_directory(os.path.join('static', 'profile_pictures'), filename)
    
    @app.route('/about')
    def about():
        return render_template('about.html')
    
    # Create database and default admin account
    with app.app_context():
        db.create_all()
        create_default_admin()
    
    return app

if __name__ == '__main__':
    app = create_app()
    # Run the application in development mode
    app.run(
        host='127.0.0.1',  # Only allow local connections in development
        port=5000,
        debug=True  # Enable debug mode
    ) 
