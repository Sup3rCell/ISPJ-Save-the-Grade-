from flask import Blueprint, render_template, abort, request, session, flash, redirect, url_for, current_app, jsonify, send_file
from flask_login import login_required, current_user
from datetime import datetime
import os
import io
import base64
import hashlib
from werkzeug.utils import secure_filename
from models import db, Document, DocVersion, User, AccessLog
from modules.document_security import DocumentEncryption
from modules.redaction import RedactionEngine
from modules.logging import log_attempt

doc_bp = Blueprint('doc', __name__)

# Initialize engines
encryption_engine = DocumentEncryption()
redaction_engine = RedactionEngine()

ALLOWED_EXTENSIONS = {'txt', 'md', 'csv', 'log', 'pdf'} # For MVP demo of redaction

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

from modules.risk_manager import RiskManager

@doc_bp.route('/dashboard')
@login_required
def dashboard():
    # Real DB Query
    documents = Document.query.filter_by(owner_id=current_user.id, is_deleted=False).all()
    
    # Get Risk Score
    risk_stats = RiskManager.get_current_risk(current_user.id)
    current_risk_score = risk_stats.get('score', 0)
    
    # Format for template
    docs_display = []
    for d in documents:
        docs_display.append({
            'id': d.id,
            'name': d.filename,
            'owner': d.owner.username,
            'date': d.updated_at.strftime('%b %d, %Y %I:%M %p'),
            'classification': d.classification,
            'size': f"{d.file_size / 1024:.1f} KB" if d.file_size < 1024 * 1024 else f"{d.file_size / (1024 * 1024):.1f} MB",
            'is_starred': d.is_starred,
            'risk_score': current_risk_score
        })
        
    return render_template('documents/dashboard.html', documents=docs_display, current_risk_score=current_risk_score)

from modules.classification import DocumentClassifier

classifier_engine = DocumentClassifier()

@doc_bp.route('/upload', methods=['POST'])
@login_required
def upload_document():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'error': 'No selected file'}), 400

    # DUPLICATE CHECK & RESOLUTION
    resolution = request.form.get('resolution') # 'replace' or 'rename'
    existing_doc = Document.query.filter_by(owner_id=current_user.id, filename=file.filename, is_deleted=False).first()
    
    if existing_doc:
        if resolution == 'replace':
            # Soft delete the old one so we can upload the new one "in place" (conceptually)
            existing_doc.is_deleted = True
            db.session.commit()
            # Proceed to upload...
            
        elif resolution == 'rename':
            # Generate new name: filename.txt -> filename (1).txt
            base, ext = os.path.splitext(file.filename)
            counter = 1
            while True:
                new_filename = f"{base} ({counter}){ext}"
                check_doc = Document.query.filter_by(owner_id=current_user.id, filename=new_filename, is_deleted=False).first()
                if not check_doc:
                    file.filename = new_filename # Update the filename object
                    break
                counter += 1
        else:
            # No resolution provided, return Conflict
            return jsonify({'status': 'conflict', 'error': f'File "{file.filename}" already exists.'}), 409
        
    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            original_content = file.read().decode('utf-8', errors='ignore')
            
            # 0. Classification (Auto-Detection)
            user_classification = request.form.get('classification', 'internal')
            classification_result = classifier_engine.classify(original_content, user_classification)
            final_classification = classification_result['level']
            
            warning_msg = None
            if final_classification != user_classification:
                reasons = "; ".join(classification_result['reasons'])
                warning_msg = f"Security Alert: Classification upgraded to {final_classification.upper()}. Reason: {reasons}"
            
            # 1. Redaction (Process in memory)
            # Use file stream to handle PDFs and large files
            file.seek(0)
            mime = file.content_type or 'application/octet-stream'
            redacted_bytes = redaction_engine.process_file_stream(file, mime)
            
            # 2. Encryption (Memory)
            # Encrypt the REDACTED bytes
            encryption_result = encryption_engine.encrypt_data(redacted_bytes)
            
            # 3. Storage (Database BLOB)
            # Store encrypted content + tag directly in the DB
            final_ciphertext = encryption_result['ciphertext'] + encryption_result['tag']
            
            file_size = len(redacted_bytes)
            
            # Calculate SHA-256 of the redacted content
            file_hash = hashlib.sha256(redacted_bytes).hexdigest()
            
            # Base64 encode key/iv for DB
            key_b64 = base64.b64encode(encryption_result['key']).decode('utf-8')
            iv_b64 = base64.b64encode(encryption_result['iv']).decode('utf-8')

            # Calculate Risk (Mocking RiskManager call)
            # In a real scenario, we might call RiskManager.calculate_upload_risk(...)
            
            new_doc = Document(
                filename=filename,
                original_filename=file.filename,
                filepath=None, # No longer used
                file_data=final_ciphertext, # Store BLOB
                file_size=file_size,
                mime_type=mime,
                classification=final_classification,
                owner_id=current_user.id,
                # Encryption Metadata
                is_encrypted=True,
                encryption_key=key_b64,
                encryption_iv=iv_b64
            ) 
            
            
            db.session.add(new_doc)
            db.session.flush() 
            
            # 4. Create Version 1
            new_version = DocVersion(
                document_id=new_doc.id,
                version_number=1,
                file_hash=file_hash,
                file_data=final_ciphertext, # Store BLOB for version too
                file_size=file_size,
                created_by=current_user.id,
                encryption_key=key_b64,
                encryption_iv=iv_b64
            )
            db.session.add(new_version)
            db.session.commit()
            
            return jsonify({
                'status': 'success', 
                'message': 'File uploaded successfully!',
                'classification': final_classification,
                'warning': warning_msg
            })
            
        except Exception as e:
            db.session.rollback()
            print(f"Upload Error: {e}")
            return jsonify({'status': 'error', 'error': str(e)}), 500
            
    return jsonify({'status': 'error', 'error': 'File type not allowed'}), 400

@doc_bp.route('/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    # Check ownership
    if doc.owner_id != current_user.id:
        abort(403)
        
    try:
        # Soft delete
        doc.is_deleted = True
        db.session.commit()
        flash(f'Document "{doc.filename}" moved to Trash.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting document: {str(e)}', 'danger')
        
    return redirect(url_for('doc.dashboard'))

@doc_bp.route('/trash')
@login_required
def trash():
    # Fetch deleted documents
    documents = Document.query.filter_by(owner_id=current_user.id, is_deleted=True).all()
    
    docs_display = []
    for d in documents:
        docs_display.append({
            'id': d.id,
            'name': d.filename,
            'owner': d.owner.username,
            'date': d.updated_at.strftime('%b %d'),
            'classification': d.classification,
            'size': f"{d.file_size / 1024:.1f} KB" if d.file_size < 1024 * 1024 else f"{d.file_size / (1024 * 1024):.1f} MB"
        })
        
    return render_template('documents/trash.html', documents=docs_display)

@doc_bp.route('/restore/<int:doc_id>', methods=['POST'])
@login_required
def restore_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != current_user.id:
        abort(403)
        
    try:
        doc.is_deleted = False
        db.session.commit()
        flash(f'Document "{doc.filename}" restored.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error restoring document: {str(e)}', 'danger')
        
    return redirect(url_for('doc.trash'))

@doc_bp.route('/delete_forever/<int:doc_id>', methods=['POST'])
@login_required
def delete_forever(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != current_user.id:
        abort(403)
        
    try:
        # Physical deletion (DB constraint might handle versions cascade if configured)
        # We just delete the record, which contains the BLOB.
            
        db.session.delete(doc)
        db.session.commit()
        flash(f'Document "{doc.filename}" permanently deleted.', 'warning')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting document: {str(e)}', 'danger')
        
    return redirect(url_for('doc.trash'))

@doc_bp.route('/view/<int:doc_id>')
@login_required
def view_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    # RBAC/Ownership Check
    if doc.owner_id != current_user.id:
        abort(403)
        
    # Amount of bytes to read for preview if it's a huge file
    # For now, we read all (VM memory limit applies)
    
    content_str = ""
    is_pdf = doc.mime_type == 'application/pdf'
    pdf_b64 = None
    
    try:
        # 1. Read Encrypted Content
        # 1. Read Encrypted Content (From DB)
        if not doc.file_data:
             return "File content missing.", 404

        # Read the file data
        file_content = doc.file_data
            
        # 2. Decrypt
        if doc.is_encrypted:
            # Extract Tag
            tag = file_content[-16:]
            ciphertext = file_content[:-16]
            
            # Decode Keys
            key = base64.b64decode(doc.encryption_key)
            iv = base64.b64decode(doc.encryption_iv)
            
            decrypted_bytes = encryption_engine.decrypt_data(ciphertext, key, iv, tag)
        else:
            decrypted_bytes = file_content
            
        # 3. Handle Content Type
        if is_pdf:
            # For PDF, we send base64 to template to render in iframe
            pdf_b64 = base64.b64encode(decrypted_bytes).decode('utf-8')
        else:
            # Text based
            content_str = decrypted_bytes.decode('utf-8', errors='replace')
        
    except Exception as e:
        current_app.logger.error(f"Decryption Error for doc {doc_id}: {e}")
        flash("Error decrypting document.", "danger")
        content_str = "[Error: Decryption Failed]"
        
    # Risk Calculation (Mocking the call structure for now, user to replace with real engine)
    # Using existing session risk if available
    risk_score = session.get('risk_score', 0)
    
    # Generate watermark
    watermark_text = f"{current_user.username} | {request.remote_addr} | {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    
    # Pass dict object to template as it expects 'document.name', 'document.content'
    doc_obj = {
        'name': doc.filename,
        'classification': doc.classification,
        'content': content_str,
        'is_pdf': is_pdf,
        'pdf_data': pdf_b64
    }
    
    return render_template('documents/secure_viewer.html', 
                         document=doc_obj, 
                         watermark_text=watermark_text,
                         risk_score=risk_score)

# ============================================
# SESSION CONTINUOUS VERIFICATION (AJAX)
# ============================================

@doc_bp.route('/session/verify_session', methods=['POST'])
@login_required
def verify_session():
    """Endpoint polled by the secure viewer to check session risk continuously"""
    # Simply return current session risk for now
    # Real implementation would re-evaluate risk
    return jsonify({
        'risk_score': session.get('risk_score', 0),
        'action': 'allow', # placeholder
        'risk_factors': []
    }), 200

# ============================================
# STARRED FILES & SHARING
# ============================================

@doc_bp.route('/star/<int:doc_id>', methods=['POST'])
@login_required
def toggle_star(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    
    doc.is_starred = not doc.is_starred
    db.session.commit()
    return jsonify({'status': 'success', 'is_starred': doc.is_starred})

@doc_bp.route('/starred')
@login_required
def starred_dashboard():
    # Similar to dashboard but filtered
    documents = Document.query.filter_by(owner_id=current_user.id, is_deleted=False, is_starred=True).all()
    
    # Get Risk Score
    risk_stats = RiskManager.get_current_risk(current_user.id)
    current_risk_score = risk_stats.get('score', 0)
    
    docs_display = []
    for d in documents:
        docs_display.append({
            'id': d.id,
            'name': d.filename,
            'owner': d.owner.username,
            'date': d.updated_at.strftime('%b %d, %Y %I:%M %p'),
            'classification': d.classification,
            'size': f"{d.file_size / 1024:.1f} KB" if d.file_size < 1024 * 1024 else f"{d.file_size / (1024 * 1024):.1f} MB",
            'is_starred': d.is_starred,
            'risk_score': current_risk_score 
        })
        
    return render_template('documents/starred.html', documents=docs_display, current_risk_score=current_risk_score)

import uuid

@doc_bp.route('/share/<int:doc_id>', methods=['POST'])
@login_required
def generate_share_link(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    
    # Policy Update: Allowed for all, but RBAC protected on access
        
    if not doc.share_link_token:
        doc.share_link_token = uuid.uuid4().hex
        db.session.commit()
    
    share_url = url_for('doc.access_shared_document', token=doc.share_link_token, _external=True)
    return jsonify({'status': 'success', 'link': share_url})

@doc_bp.route('/s/<token>')
@login_required
def access_shared_document(token):
    doc = Document.query.filter_by(share_link_token=token).first_or_404()
    
    # NEW: RBAC Check for Link Sharing
    if doc.classification in ['restricted', 'confidential']:
        if current_user.role not in ['admin', 'manager']:
            # Log the denied attempt
            log_attempt(
                 current_user.id, 
                 'ACCESS_DENIED_RBAC_LINK', 
                 60, 
                 'DENIED', 
                 action_details={'doc_id': doc.id, 'classification': doc.classification, 'user_role': current_user.role}
            )
            flash(f"Access Denied: You do not have the required clearance ({doc.classification}).", "danger")
            return redirect(url_for('doc.dashboard'))

    # Decrypt content for display (similar to view_document)
    content_str = ""
    try:
        # 1. Read Encrypted File
        # 1. Read Encrypted Content (From DB BLOB)
        if not doc.file_data:
             return "File content missing.", 404

        # Read the file data
        file_content = doc.file_data
            
        # 2. Decrypt
        if doc.is_encrypted:
            # Extract Tag
            tag = file_content[-16:]
            ciphertext = file_content[:-16]
            
            # Decode Keys
            key = base64.b64decode(doc.encryption_key)
            iv = base64.b64decode(doc.encryption_iv)
            
            decrypted_bytes = encryption_engine.decrypt_data(ciphertext, key, iv, tag)
        else:
            decrypted_bytes = file_content
            
        # 3. Handle Content Type
        if doc.mime_type == 'application/pdf':
            pdf_b64 = base64.b64encode(decrypted_bytes).decode('utf-8')
            content_str = "" # No text content
        else:
            content_str = decrypted_bytes.decode('utf-8', errors='replace')
            
    except Exception as e:
        print(f"Decryption Error: {e}")
        content_str = "[Error: Decryption Failed]"

    # Risk Calculation
    risk_score = session.get('risk_score', 0)
    watermark_text = f"SHARED | {current_user.username} | {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    
    doc_obj = {
        'name': doc.filename,
        'classification': doc.classification,
        'content': content_str,
        'is_pdf': doc.mime_type == 'application/pdf',
        'pdf_data': pdf_b64 if doc.mime_type == 'application/pdf' else None
    }
    
    return render_template('documents/secure_viewer.html', 
                         document=doc_obj, 
                         watermark_text=watermark_text,
                         risk_score=risk_score)

# ============================================
# P2P SHARING (INVITE & ACCEPT)
# ============================================

from models import DocumentShare

@doc_bp.route('/share/invite/<int:doc_id>', methods=['POST'])
@login_required
def share_invite(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    
    email = request.form.get('email')
    if not email:
        return jsonify({'status': 'error', 'message': 'Email is required'}), 400
        
    recipient = User.query.filter_by(email=email).first()
    if not recipient:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
    if recipient.id == current_user.id:
        return jsonify({'status': 'error', 'message': 'Cannot share with yourself'}), 400
        
    # Check if already shared
    existing = DocumentShare.query.filter_by(document_id=doc.id, shared_with_user_id=recipient.id).first()
    if existing:
        return jsonify({'status': 'error', 'message': f'Already shared with this user (Status: {existing.status})'}), 400
        
    # Create Share
    share = DocumentShare(
        document_id=doc.id,
        shared_with_user_id=recipient.id,
        shared_by_user_id=current_user.id,
        status='pending'
    )
    db.session.add(share)
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': f'Invitation sent to {recipient.username}'})

@doc_bp.route('/share/respond/<int:share_id>/<string:action>', methods=['POST'])
@login_required
def respond_share(share_id, action):
    share = DocumentShare.query.get_or_404(share_id)
    
    # Only the recipient can accept/reject
    if share.shared_with_user_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
        
    if action not in ['accept', 'reject']:
        return jsonify({'status': 'error', 'message': 'Invalid action'}), 400
        
    if action == 'accept':
        share.status = 'accepted'
        msg = 'Invitation accepted.'
    else:
        share.status = 'rejected'
        msg = 'Invitation rejected.'
        
    db.session.commit()
    return jsonify({'status': 'success', 'message': msg})

@doc_bp.route('/shared_with_me')
@login_required
def shared_with_me():
    # Get all shares where user is recipient
    shares = DocumentShare.query.filter_by(shared_with_user_id=current_user.id).all()
    
    # Process for display
    shared_docs = []
    pending_count = 0
    
    for s in shares:
        if s.status == 'pending':
            pending_count += 1
        
        if s.status == 'rejected':
            continue

        d = s.document
        shared_docs.append({
            'share_id': s.id,
            'doc_id': d.id,
            'name': d.filename,
            'owner': d.owner.username, 
            'date': s.created_at.strftime('%b %d, %Y'),
            'status': s.status,
            'classification': d.classification,
            'size': f"{d.file_size / 1024:.1f} KB" if d.file_size < 1024 * 1024 else f"{d.file_size / (1024 * 1024):.1f} MB",
        })
        
    return render_template('documents/shared_with_me.html', shares=shared_docs, pending_count=pending_count)

@doc_bp.route('/view/shared/<int:doc_id>')
@login_required
def view_shared_p2p(doc_id):
    # Validates if current user has an ACTIVATED share for this doc
    share = DocumentShare.query.filter_by(document_id=doc_id, shared_with_user_id=current_user.id, status='accepted').first()
    if not share:
       # Fallback to owner check or redirect
       doc = Document.query.get_or_404(doc_id)
       if doc.owner_id == current_user.id:
           return redirect(url_for('doc.view_document', doc_id=doc_id))
       return "Access Denied or Invitation Pending", 403

    doc = share.document
    
    # RBAC Classification Check
    # If document is 'restricted' or 'confidential', ensure user has appropriate role
    if doc.classification in ['restricted', 'confidential']:
        if current_user.role not in ['admin', 'manager']:
            log_attempt(
                 current_user.id, 
                 'ACCESS_DENIED_RBAC_SHARED', 
                 60, 
                 'DENIED', 
                 action_details={'doc_id': doc.id, 'classification': doc.classification, 'user_role': current_user.role}
            )
            flash(f"Access Denied: You do not have the required clearance ({doc.classification}).", "danger")
            return redirect(url_for('doc.dashboard'))
    
    # Decryption logic
    content_str = ""
    try:
        if doc.file_data:
            encrypted_data = doc.file_data
            
            # Decrypt
            key_bytes = base64.b64decode(doc.encryption_key)
            iv_bytes = base64.b64decode(doc.encryption_iv)
            
            # Extract tags (assuming same format: ciphertext + tag)
            tag = encrypted_data[-16:]
            ciphertext = encrypted_data[:-16]
            
            decrypted_bytes = encryption_engine.decrypt_data(ciphertext, key_bytes, iv_bytes, tag)
            content_str = decrypted_bytes.decode('utf-8')
        else:
            content_str = "[Error: File Content Missing]"
    except Exception as e:
        print(f"Decryption Error: {e}")
        content_str = "[Error: Decryption Failed]"

    watermark_text = f"SHARED-P2P | {current_user.username} | {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    
    doc_obj = {
        'name': doc.filename,
        'classification': doc.classification,
        'content': content_str
    }
    
    return render_template('documents/secure_viewer.html', 
                         document=doc_obj, 
                         watermark_text=watermark_text,
                         risk_score=0)
