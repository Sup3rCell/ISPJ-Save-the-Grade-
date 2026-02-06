from flask import request
from models import db, AccessLog
from datetime import datetime

def log_attempt(user_id, action, risk, outcome, email_attempt=None, document_id=None):
    """
    Central function to log all security-relevant events to the AccessLog table.
    """
    log = AccessLog(
        user_id=user_id,
        document_id=document_id,  # New: Added optional document ID
        action=action,
        ip_address=request.remote_addr,
        device_info=request.headers.get('User-Agent'),
        risk_score=risk,
        outcome=outcome,
        timestamp=datetime.utcnow()
    )

    # Log the attempted email/location detail if the login failed (user_id is None)
    if user_id is None and email_attempt:
        log.location = f"Attempted Email: {email_attempt}"
    
    # We will log Geo-IP location here once Teammate 2 implements Geo-IP lookups.
    
    db.session.add(log)
    db.session.commit()