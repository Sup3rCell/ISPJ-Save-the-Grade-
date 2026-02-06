from flask import request, jsonify, session, current_app
from functools import wraps
from datetime import datetime, timedelta
from modules.risk_engine import calculate_risk_score  # Updated below
from models import AccessLog, db

def verify_session_risk():
    """Core mid-session risk re-calc. Returns dict: {'risk_score': int, 'action': str, 'reasons': list}"""
    user_id = session.get('user_id')
    if not user_id:
        return {'risk_score': 100, 'action': 'terminate', 'reasons': ['No session']}

    # Re-run full risk (identity + location/device stubs)
    risk_score, reasons = calculate_risk_score(user_id)  # Pass user_id now

    # Determine action based on risk
    if risk_score > 80:
        action = 'terminate'  # Immediate logout
    elif risk_score > 60:
        action = 'restrict'   # View-only, step-up next
    elif risk_score > 40:
        action = 'stepup'     # Require OTP
    else:
        action = 'allow'

    # Log the check
    log = AccessLog(
        user_id=user_id,
        action=f'SECTION_VERIFY_{action.upper()}',
        risk_score=risk_score,
        ip=request.remote_addr,
        timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()

    return {'risk_score': risk_score, 'action': action, 'reasons': reasons}

def requires_low_risk(f):
    """Decorator for protected routes: auto-checks risk."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        result = verify_session_risk()
        if result['action'] != 'allow':
            return jsonify(result), 403  # JSON for AJAX
        return f(*args, **kwargs)
    return decorated_function
