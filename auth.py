from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template, flash
from flask_login import login_user, logout_user, login_required, current_user
from models import User, db, AuditLog, ActivityLog
from utils.security import SecurityUtils
from authlib.integrations.flask_client import OAuth
import os
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from datetime import datetime
import mysql.connector
from mysql.connector import Error
import re
from utils.two_factor import TwoFactorAuth
from werkzeug.utils import secure_filename
import uuid

auth = Blueprint('auth', __name__)
oauth = OAuth()

# OAuth provider setup
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'}
)

github = oauth.register(
    name='github',
    client_id='Ov23linuiV0nxknU7vCh',
    client_secret='b7dce9d3b8824f6d1e93f6b7e29657ea0ced5b6b',
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'}
)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        try:
            user = User.query.filter_by(email=email).first()
            try:
                if not user or not user.check_password(password):
                    flash('Invalid email or password', 'danger')
                    return redirect(url_for('auth.login'))
            except ValueError:
                # Handle unsupported hash type or other hash errors gracefully
                flash('Invalid email or password', 'danger')
                return redirect(url_for('auth.login'))
            
            if not user.is_active:
                flash('Your account has been disabled. Please contact support', 'warning')
                return redirect(url_for('auth.login'))
            
            # If two-factor authentication is fully enabled
            if user.is_two_factor_enabled:
                if user.two_factor_secret:
                    session['pending_user_id'] = user.id
                    return redirect(url_for('auth.verify_2fa'))
                else:
                    # If two-factor authentication is not fully set up, redirect to setup page
                    login_user(user, remember=remember)
                    return redirect(url_for('auth.setup_2fa'))
            
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            login_user(user, remember=remember)
            
            # Log login
            log_activity(user.id, 'login', f'User logged in from {request.remote_addr}')
            
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('home')
            
            return redirect(next_page)
            
        except Error as e:
            flash('Database error. Please try again', 'danger')
            print(f"Database error: {str(e)}")
            return redirect(url_for('auth.login'))
    
    return render_template('auth/login.html')

@auth.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Verify two-factor authentication"""
    if request.method == 'GET':
        if 'pending_user_id' not in session:
            return redirect(url_for('auth.login'))
        return render_template('auth/verify_2fa.html')
    
    if request.method == 'POST':
        if 'pending_user_id' not in session:
            flash('Invalid session', 'danger')
            return redirect(url_for('auth.login'))
        
        token = request.form.get('token')
        if not token:
            flash('Please enter verification code', 'danger')
            return redirect(url_for('auth.verify_2fa'))
        
        user = User.query.get(session['pending_user_id'])
        if not user:
            session.pop('pending_user_id', None)
            flash('Invalid user', 'danger')
            return redirect(url_for('auth.login'))
        
        # Verify code
        if TwoFactorAuth.verify_totp(user.two_factor_secret, token):
            login_user(user)
            session.pop('pending_user_id', None)
            log_audit(user.id, '2fa_verification', 'Two-factor authentication verified successfully')
            return redirect(url_for('home'))
        
        # Verify backup codes
        if user.verify_backup_code(token):
            login_user(user)
            session.pop('pending_user_id', None)
            log_audit(user.id, 'backup_code_used', 'Backup code used')
            return redirect(url_for('home'))
        
        flash('Invalid verification code', 'danger')
        return redirect(url_for('auth.verify_2fa'))

@auth.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    """Setup two-factor authentication"""
    if request.method == 'GET':
        # Create new secret if not exists
        if not current_user.two_factor_secret:
            secret = TwoFactorAuth.generate_secret()
            current_user.two_factor_secret = secret
            db.session.commit()
        
        # Create QR code
        uri = TwoFactorAuth.generate_totp_uri(current_user.two_factor_secret, current_user.email)
        qr_code = TwoFactorAuth.generate_qr_code(uri)
        
        # Create backup codes
        backup_codes = TwoFactorAuth.generate_backup_codes()
        current_user.set_backup_codes(backup_codes)
        
        return render_template('auth/setup_2fa.html', 
                             secret=current_user.two_factor_secret,
                             qr_code=qr_code,
                             backup_codes=backup_codes)
    
    if request.method == 'POST':
        token = request.form.get('token')
        if not token:
            flash('Please enter verification code', 'danger')
            return redirect(url_for('auth.setup_2fa'))
            
        if TwoFactorAuth.verify_totp(current_user.two_factor_secret, token):
            current_user.is_two_factor_enabled = True
            db.session.commit()
            flash('Two-factor authentication enabled successfully', 'success')
            return redirect(url_for('auth.settings'))
        else:
            flash('Invalid verification code. Please try again', 'danger')
            return redirect(url_for('auth.setup_2fa'))

@auth.route('/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    """Enable two-factor authentication"""
    data = request.get_json()
    if SecurityUtils.verify_totp(current_user.two_fa_secret, data['token']):
        current_user.two_fa_enabled = True
        db.session.commit()
        log_audit(current_user.id, '2fa_enabled', 'Two-factor authentication enabled')
        return jsonify({'message': 'Two-factor authentication enabled successfully'})
    
    return jsonify({'error': 'Invalid token'}), 401

@auth.route('/login/google')
def google_login():
    """Login with Google"""
    return google.authorize_redirect(url_for('auth.google_callback', _external=True))

@auth.route('/login/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    
    user = User.query.filter_by(oauth_id=user_info['id'], oauth_provider='google').first()
    if not user:
        user = User(
            email=user_info['email'],
            name=user_info['name'],
            oauth_provider='google',
            oauth_id=user_info['id']
        )
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    log_audit(user.id, 'oauth_login', 'Login via Google')
    return redirect(url_for('home'))

@auth.route('/login/github')
def github_login():
    """Login with GitHub"""
    return github.authorize_redirect(url_for('auth.github_callback', _external=True))

@auth.route('/login/github/callback')
def github_callback():
    """Handle GitHub OAuth callback"""
    token = github.authorize_access_token()
    resp = github.get('user')
    user_info = resp.json()
    
    user = User.query.filter_by(oauth_id=str(user_info['id']), oauth_provider='github').first()
    if not user:
        user = User(
            email=user_info['email'],
            name=user_info['name'],
            oauth_provider='github',
            oauth_id=str(user_info['id'])
        )
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    log_audit(user.id, 'oauth_login', 'Login via GitHub')
    return redirect(url_for('home'))

@auth.route('/logout')
@login_required
def logout():
    """Logout user"""
    log_activity(current_user.id, 'logout', f'User logged out from {request.remote_addr}')
    logout_user()
    return redirect(url_for('index'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Check password match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('auth.register'))
        
        # Check password strength
        if not SecurityUtils.is_strong_password(password):
            flash('Password is weak. Must be at least 8 characters and include uppercase, lowercase, numbers, and special characters', 'danger')
            return redirect(url_for('auth.register'))
        
        # Check if email exists
        if User.query.filter_by(email=email).first():
            flash('Email already in use', 'danger')
            return redirect(url_for('auth.register'))
        
        try:
            # Create new user
            user = User(
                name=name,
                email=email,
                is_active=True
            )
            user.set_password(password)
            
            # Handle profile picture
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename:
                    # Create unique filename
                    filename = secure_filename(file.filename)
                    ext = filename.rsplit('.', 1)[1].lower()
                    new_filename = f"{uuid.uuid4()}.{ext}"
                    
                    # Save file
                    profile_dir = os.path.join('static', 'profile_pictures')
                    os.makedirs(profile_dir, exist_ok=True)
                    file_path = os.path.join(profile_dir, new_filename)
                    file.save(file_path)
                    
                    # Update profile picture path in database
                    user.profile_picture = new_filename
            
            db.session.add(user)
            db.session.commit()
            
            # Log activity
            log_activity(user.id, 'register', f'New account created from {request.remote_addr}')
            
            flash('Account created successfully! You can now login', 'success')
            return redirect(url_for('auth.login'))
            
        except Error as e:
            flash('Database error occurred. Please try again', 'danger')
            print(f"Database error: {str(e)}")
            return redirect(url_for('auth.register'))
    
    return render_template('auth/register.html')

@auth.route('/profile')
@login_required
def profile():
    """View user profile"""
    return render_template('auth/profile.html')

@auth.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    name = request.form.get('name')
    phone = request.form.get('phone')
    bio = request.form.get('bio')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not name:
        flash('Name is required.', 'danger')
        return redirect(url_for('auth.profile'))
    
    try:
        current_user.name = name
        current_user.phone = phone
        current_user.bio = bio
        
        if current_password and new_password:
            if not current_user.check_password(current_password):
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('auth.profile'))
            
            if new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
                return redirect(url_for('auth.profile'))
            
            current_user.set_password(new_password)
        
        db.session.commit()
        log_audit(current_user.id, 'profile_update', 'Profile updated')
        flash('Profile updated successfully.', 'success')
        
    except Error as e:
        flash('Database error occurred. Please try again later.', 'danger')
        print(f"Database error: {str(e)}")
    
    return redirect(url_for('auth.profile'))

@auth.route('/settings')
@login_required
def settings():
    """View user settings"""
    return render_template('auth/settings.html')

@auth.route('/settings/notifications', methods=['POST'])
@login_required
def update_notification_settings():
    """Update notification settings"""
    try:
        current_user.email_notifications = request.form.get('email_notifications') == 'true'
        current_user.push_notifications = request.form.get('push_notifications') == 'true'
        db.session.commit()
        return jsonify({'message': 'Notification settings updated successfully'})
    except Error as e:
        return jsonify({'error': 'Failed to update notification settings'}), 500

@auth.route('/settings/customization', methods=['POST'])
@login_required
def update_customization_settings():
    """Update customization settings"""
    try:
        current_user.theme = request.form.get('theme')
        current_user.language = request.form.get('language')
        current_user.timezone = request.form.get('timezone')
        db.session.commit()
        flash('Customization settings updated successfully.', 'success')
    except Exception as e:
        flash('Error updating customization settings.', 'danger')
    return redirect(url_for('auth.settings'))

@auth.route('/settings/storage', methods=['POST'])
@login_required
def update_storage_settings():
    """Update storage settings"""
    try:
        current_user.storage_limit = int(request.form.get('storage_limit', 1024))
        db.session.commit()
        return jsonify({'message': 'Storage settings updated successfully'})
    except Error as e:
        return jsonify({'error': 'Failed to update storage settings'}), 500

@auth.route('/settings/security', methods=['POST'])
@login_required
def update_security_settings():
    """Update security settings"""
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    is_two_factor_enabled = request.form.get('is_two_factor_enabled') == 'on'

    # Update two-factor authentication status
    if current_user.is_two_factor_enabled != is_two_factor_enabled:
        if is_two_factor_enabled:
            # Setup 2FA if it's not already set up
            if not current_user.two_factor_secret:
                secret = SecurityUtils.generate_totp_secret()
                current_user.two_factor_secret = secret
            current_user.is_two_factor_enabled = True
        else:
            current_user.is_two_factor_enabled = False
        db.session.commit()
        flash('Two-factor authentication settings updated', 'success')

    # Update password if provided
    if current_password and new_password and confirm_password:
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('auth.settings'))
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('auth.settings'))
        
        current_user.set_password(new_password)
        db.session.commit()
        flash('Password updated successfully', 'success')
        log_audit(current_user.id, 'password_change', 'Password changed')

    return redirect(url_for('auth.settings'))

@auth.route('/update-theme', methods=['POST'])
@login_required
def update_theme():
    """Update user theme preference"""
    try:
        if request.is_json:
            data = request.get_json()
            theme = data.get('theme')
        else:
            theme = request.form.get('theme')
        if theme in ['light', 'dark']:
            current_user.theme_preference = theme
            db.session.commit()
            return jsonify({'message': 'Theme updated successfully', 'theme': theme})
        return jsonify({'error': 'Invalid theme'}), 400
    except Exception as e:
        return jsonify({'error': 'Failed to update theme'}), 500

@auth.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disable two-factor authentication"""
    token = request.form.get('token')
    if not token:
        flash('Please enter verification code', 'danger')
        return redirect(url_for('auth.settings'))
    
    if TwoFactorAuth.verify_totp(current_user.two_factor_secret, token):
        current_user.is_two_factor_enabled = False
        current_user.two_factor_secret = None
        current_user.backup_codes = None
        db.session.commit()
        flash('Two-factor authentication disabled successfully', 'success')
    else:
        flash('Invalid verification code', 'danger')
    
    return redirect(url_for('auth.settings'))

@auth.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    try:
        user_id = current_user.id
        logout_user()
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

def log_audit(user_id, action, details):
    """Log user activity"""
    log = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

def log_activity(user_id, action, description):
    """Log user activity"""
    try:
        activity = ActivityLog(
            user_id=user_id,
            action=action,
            description=description,
            ip_address=request.remote_addr
        )
        db.session.add(activity)
        db.session.commit()
    except Error as e:
        print(f"Failed to log activity: {str(e)}") 
