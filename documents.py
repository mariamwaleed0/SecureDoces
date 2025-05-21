from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, send_file, after_this_request, jsonify
from flask_login import login_required, current_user
from models import db, Document, AuditLog, ActivityLog, User
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import hashlib
from utils.crypto import encrypt_data, decrypt_data
import mimetypes
import tempfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from cryptography.fernet import Fernet

documents = Blueprint('documents', __name__)

# Allowed file types
ALLOWED_MIME_TYPES = {
    'application/pdf': '.pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
    'text/plain': '.txt'
}

MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in [ext.lstrip('.') for ext in ALLOWED_MIME_TYPES.values()]

@documents.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_document():
    """Document upload page"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        # Check file size
        file_data = file.read()
        if len(file_data) > MAX_FILE_SIZE:
            flash('File size exceeds the allowed limit (16 MB)', 'error')
            return redirect(request.url)
        
        # Check file type
        if allowed_file(file.filename):
            try:
                # Secure filename
                filename = secure_filename(file.filename)
                
                # Determine file type
                mime_type = mimetypes.guess_type(filename)[0]
                
                # Create file hash
                content_hash = hashlib.sha256(file_data).hexdigest()
                
                # Encrypt file content
                encrypted_content = encrypt_data(file_data)
                
                # Create document record in database
                document = Document(
                    filename=filename,
                    encrypted_content=encrypted_content,
                    content_hash=content_hash,
                    uploaded_by=current_user.id,
                    mime_type=mime_type,
                    file_size=len(file_data)
                )
                
                db.session.add(document)
                db.session.commit()
                
                # Log event
                document.log_modification(current_user.id, 'upload', 'Document uploaded')
                
                flash('Document uploaded successfully', 'success')
                return redirect(url_for('documents.list_documents'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error uploading document: {str(e)}', 'error')
                return redirect(request.url)
        else:
            flash('File type not allowed', 'error')
            return redirect(request.url)
    
    return render_template('documents/upload.html')

@documents.route('/')
@login_required
def list_documents():
    """Document listing page with advanced search and filtering"""
    if current_user.role == 'admin':
        query = Document.query  # Admin sees all documents
    else:
        query = Document.query.filter_by(uploaded_by=current_user.id)  # User sees only their own

    # Search by name or signature
    q = request.args.get('q', '').strip()
    if q:
        query = query.filter(
            (Document.filename.ilike(f'%{q}%')) |
            (Document.signature.ilike(f'%{q}%'))
        )

    # Filter by status
    status = request.args.get('status', '').strip()
    if status:
        if status == 'signed':
            query = query.filter(Document.signature.isnot(None))
        elif status == 'pending':
            query = query.filter(Document.signature.is_(None))
        else:
            query = query.filter(Document.status == status)

    # Filter by date
    date = request.args.get('date', '').strip()
    if date:
        try:
            date_obj = datetime.strptime(date, '%Y-%m-%d').date()
            query = query.filter(db.func.date(Document.upload_date) == date_obj)
        except Exception:
            pass

    documents = query.order_by(Document.upload_date.desc()).all()
    return render_template('documents/list.html', documents=documents)

@documents.route('/<int:doc_id>')
@login_required
def view_document(doc_id):
    """View document details"""
    document = Document.query.get_or_404(doc_id)
    
    # Check document ownership
    if document.uploaded_by != current_user.id and current_user.role != 'admin':
        flash('You are not authorized to access this document', 'error')
        return redirect(url_for('documents.list_documents'))
    
    return render_template('documents/view.html', document=document)

@documents.route('/<int:doc_id>/download')
@login_required
def download_document(doc_id):
    """Download document"""
    document = Document.query.get_or_404(doc_id)
    
    # Check document ownership
    if document.uploaded_by != current_user.id and current_user.role != 'admin':
        flash('You are not authorized to download this document', 'error')
        return redirect(url_for('documents.list_documents'))
    
    try:
        # Decrypt content
        decrypted_content = decrypt_data(document.encrypted_content)
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(decrypted_content)
            temp_path = temp_file.name
        
        @after_this_request
        def cleanup(response):
            try:
                os.unlink(temp_path)
            except Exception as e:
                current_app.logger.error(f'Error cleaning up temp file: {e}')
            return response
        
        return send_file(
            temp_path,
            mimetype=document.mime_type,
            as_attachment=True,
            download_name=document.filename
        )
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        flash(f'Error downloading document: {str(e)}', 'error')
        return redirect(url_for('documents.list_documents'))

@documents.route('/<int:doc_id>/delete', methods=['POST'])
@login_required
def delete_document(doc_id):
    """Delete document"""
    document = Document.query.get_or_404(doc_id)
    
    # Check document ownership
    if document.uploaded_by != current_user.id and current_user.role != 'admin':
        flash('You are not authorized to delete this document', 'error')
        return redirect(url_for('documents.list_documents'))
    
    db.session.delete(document)
    db.session.commit()
    
    # Log event
    try:
        document.log_modification(current_user.id, 'delete', 'Document deleted')
    except Exception:
        pass
    
    flash('Document deleted successfully', 'success')
    return redirect(url_for('documents.list_documents'))

@documents.route('/<int:doc_id>/sign')
@login_required
def sign_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    if document.uploaded_by != current_user.id and current_user.role != 'admin':
        flash('You are not authorized to sign this document', 'error')
        return redirect(url_for('documents.list_documents'))

    private_key = load_private_key()
    signature = private_key.sign(
        document.content_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    document.signature = base64.b64encode(signature).decode()
    db.session.commit()
    
    # Log event
    document.log_modification(current_user.id, 'sign', 'Document signed')
    
    flash('Document signed successfully', 'success')
    return redirect(url_for('documents.list_documents'))

def log_audit(user_id, action, details):
    """Log event in audit log"""
    log = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

def load_private_key():
    key_path = os.path.join(os.path.dirname(__file__), '../private_key.pem')
    with open(key_path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

print(Fernet.generate_key().decode())

key = os.environ.get('DOCUMENT_ENCRYPTION_KEY')
print("CURRENT ENCRYPTION KEY:", os.environ.get('DOCUMENT_ENCRYPTION_KEY'))

@documents.route('/update/<int:document_id>', methods=['POST'])
@login_required
def update_document(document_id):
    """Update document and log activity"""
    document = Document.query.get_or_404(document_id)
    
    # Check permissions - admin can edit any document, users can only edit their own
    if document.uploaded_by != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'You are not authorized to modify this document'}), 403
    
    # Check if file exists in request
    if 'file' not in request.files:
        return jsonify({'error': 'No file found'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Read file content
        content = file.read()
        
        # Update document
        document.update_document(
            user_id=current_user.id,
            new_content=content,
            new_filename=secure_filename(file.filename),
            new_status=request.form.get('status', document.status)
        )
        
        # Add IP address to activity log
        activity = ActivityLog.query.filter_by(
            user_id=current_user.id,
            action='document_update'
        ).order_by(ActivityLog.timestamp.desc()).first()
        
        if activity:
            activity.ip_address = request.remote_addr
            db.session.commit()
        
        return jsonify({
            'message': 'Document updated successfully',
            'document': {
                'id': document.id,
                'filename': document.filename,
                'status': document.status,
                'version': document.version,
                'last_modified': document.last_modified.isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'Error updating document: {str(e)}'}), 500

@documents.route('/activity-log')
@login_required
def get_activity_log():
    """View document activity log"""
    if not current_user.role == 'admin':
        return jsonify({'error': 'You are not authorized to view the activity log'}), 403
        
    activities = ActivityLog.query.filter(
        ActivityLog.action.like('document_%') | (ActivityLog.action == 'rename_document')
    ).order_by(ActivityLog.timestamp.desc()).all()
    
    # Fetch user info for each activity
    activity_list = []
    for activity in activities:
        user = User.query.get(activity.user_id)
        activity_list.append({
            'id': activity.id,
            'user_id': activity.user_id,
            'user_name': user.name if user else '',
            'user_email': user.email if user else '',
            'action': activity.action,
            'description': activity.description,
            'ip_address': activity.ip_address,
            'timestamp': activity.timestamp.isoformat()
        })
    return jsonify({'activities': activity_list})

@documents.route('/activity-log/page')
@login_required
def activity_log_page():
    """Document activity log page"""
    if not current_user.role == 'admin':
        flash('You are not authorized to access this page', 'error')
        return redirect(url_for('documents.list_documents'))
    
    return render_template('documents/activity_log.html')

@documents.route('/<int:doc_id>/rename', methods=['POST'])
@login_required
def rename_document(doc_id):
    """Rename a document (change its filename)"""
    document = Document.query.get_or_404(doc_id)
    # Only the owner or admin can rename
    if document.uploaded_by != current_user.id and current_user.role != 'admin':
        flash('You are not authorized to rename this document', 'error')
        return redirect(url_for('documents.list_documents'))
    new_name = request.form.get('new_name', '').strip()
    if not new_name:
        flash('Document name cannot be empty', 'error')
        return redirect(url_for('documents.list_documents'))
    old_name = document.filename
    document.filename = new_name
    db.session.commit()
    
    # Log event
    document.log_modification(current_user.id, 'rename', f'Renamed document from "{old_name}" to "{new_name}" (ID: {document.id})')
    
    flash('Document name updated successfully', 'success')
    return redirect(url_for('documents.list_documents'))
