from flask import Blueprint, render_template, abort, request, session, flash
from flask_login import login_required, current_user
from datetime import datetime
import os

doc_bp = Blueprint('doc', __name__)

def get_document_by_id(doc_id):
    """
    TODO: Replace with real DB query tomorrow
    For now returns dummy data matching your dashboard
    """
    dummy_docs = {
        1: {'id': 1, 'name': 'Project_Specs.pdf', 'content': '# Project Specifications\n\nThis is **secure content** that should be watermarked and protected from copy/print/download.\n\n- Item 1\n- Item 2\n\nConfidential data.', 'classification': 'Internal'},
        2: {'id': 2, 'name': 'Salary_Report_2025.xlsx', 'content': '## Salary Report 2025\n\n| Employee | Salary |\n|----------|--------|\n| Alice    | $85K   |\n| Bob      | $92K   |\n\n**Confidential - View Only**', 'classification': 'Confidential'},
        3: {'id': 3, 'name': 'Public_Memo.docx', 'content': '## Public Memo\n\nThis is public information.', 'classification': 'Public'},
    }
    return dummy_docs.get(doc_id)

def compute_risk_score():
    """
    TODO: Replace with real risk engine from modules/risk_engine.py tomorrow
    """
    return 35  # Dummy low risk

def user_can_view_document(user, doc):
    """
    TODO: Replace with real RBAC + classification logic
    """
    if getattr(user, 'is_admin', False):
        return True
    # For now, allow all logged-in users
    return True

@doc_bp.route('/dashboard')
@login_required
def dashboard():
    documents = [
        {'id': 1, 'name': 'Project_Specs.pdf', 'owner': 'Alice', 'date': 'May 16', 'classification': 'Internal'},
        {'id': 2, 'name': 'Salary_Report_2025.xlsx', 'owner': 'Bob', 'date': 'May 10', 'classification': 'Confidential'},
        {'id': 3, 'name': 'Public_Memo.docx', 'owner': 'Me', 'date': 'Nov 22', 'classification': 'Public'},
    ]
    return render_template('documents/dashboard.html', documents=documents)

@doc_bp.route('/view/<int:doc_id>')
@login_required
def view_document(doc_id):
    # 1. Load document (dummy now, real DB tomorrow)
    doc = get_document_by_id(doc_id)
    if not doc:
        abort(404)
    
    # 2. Zero-Trust Risk Check (dummy now, real tomorrow)
    risk_score = compute_risk_score()
    session['risk_score'] = risk_score  # Makes it show in dashboard
    
    if risk_score > 80:
        flash("High risk detected. Access denied.", "danger")
        abort(403)
    
    # 3. RBAC Check (dummy now, real tomorrow)
    if not user_can_view_document(current_user, doc):
        abort(403)
    
    # 4. Generate watermark
    watermark_text = f"{current_user.username} | {request.remote_addr} | {datetime.now().strftime('%Y-%m-%d %H:%M')} | Risk:{risk_score}%"
    
    return render_template('documents/secure_viewer.html', 
                         document=doc, 
                         watermark_text=watermark_text,
                         risk_score=risk_score)
