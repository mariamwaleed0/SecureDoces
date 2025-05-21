from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from models import db, User, ActivityLog
from datetime import datetime

admin = Blueprint('admin', __name__)

@admin.before_request
def check_admin():
    """التحقق من أن المستخدم لديه صلاحيات المسؤول"""
    if not current_user.is_authenticated or current_user.role != 'admin':
        flash('غير مصرح لك بالوصول إلى هذه الصفحة', 'error')
        return redirect(url_for('dashboard'))

@admin.route('/user')
@login_required
def manage_users():
    """عرض قائمة المستخدمين وإدارتهم"""
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@admin.route('/user/<int:user_id>/toggle-status', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    """تفعيل/تعطيل حساب مستخدم"""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('لا يمكنك تغيير حالة حسابك الخاص', 'error')
    else:
        user.is_active = not user.is_active
        db.session.commit()
        status = 'تفعيل' if user.is_active else 'تعطيل'
        flash(f'تم {status} حساب {user.email} بنجاح', 'success')
    return redirect(url_for('admin.manage_users'))

@admin.route('/user/<int:user_id>/change-role', methods=['POST'])
@login_required
def change_user_role(user_id):
    """تغيير دور المستخدم"""
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    
    if user.id == current_user.id:
        flash('لا يمكنك تغيير دور حسابك الخاص', 'error')
    elif new_role in ['user', 'admin']:
        user.role = new_role
        db.session.commit()
        flash(f'تم تغيير دور {user.email} إلى {new_role} بنجاح', 'success')
    else:
        flash('دور غير صالح', 'error')
    
    return redirect(url_for('admin.manage_users'))

@admin.route('/user/add', methods=['POST'])
@login_required
def add_user():
    """إضافة مستخدم جديد من لوحة الإدارة"""
    if current_user.role != 'admin':
        flash('غير مصرح لك بإضافة مستخدمين', 'error')
        return redirect(url_for('admin.manage_users'))

    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role', 'user')

    if not (name and email and password):
        flash('جميع الحقول مطلوبة', 'error')
        return redirect(url_for('admin.manage_users'))

    if User.query.filter_by(email=email).first():
        flash('البريد الإلكتروني مستخدم بالفعل', 'error')
        return redirect(url_for('admin.manage_users'))

    user = User(name=name, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    flash('تم إضافة المستخدم بنجاح', 'success')
    return redirect(url_for('admin.manage_users'))

@admin.route('/activity-log')
@login_required
def activity_log():
    if current_user.role != 'admin':
        flash('غير مصرح لك بالوصول إلى هذه الصفحة', 'error')
        return redirect(url_for('dashboard'))

    q = request.args.get('q', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    action = request.args.get('action', '').strip()

    logs_query = db.session.query(ActivityLog, User).join(User, ActivityLog.user_id == User.id, isouter=True)
    if q:
        logs_query = logs_query.filter(
            (User.email.ilike(f'%{q}%')) |
            (User.name.ilike(f'%{q}%')) |
            (ActivityLog.action.ilike(f'%{q}%')) |
            (ActivityLog.description.ilike(f'%{q}%'))
        )
    if action:
        logs_query = logs_query.filter(ActivityLog.action == action)
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d')
            logs_query = logs_query.filter(ActivityLog.timestamp >= from_date)
        except Exception:
            pass
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d')
            # أضف يوم كامل ليشمل اليوم الأخير
            to_date = to_date.replace(hour=23, minute=59, second=59)
            logs_query = logs_query.filter(ActivityLog.timestamp <= to_date)
        except Exception:
            pass
    logs = logs_query.order_by(ActivityLog.timestamp.desc()).limit(200).all()
    return render_template('admin/activity_log.html', logs=logs, q=q) 