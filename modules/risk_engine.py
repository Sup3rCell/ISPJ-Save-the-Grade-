from datetime import datetime, timedelta  # Fixed: Added timedelta
from models import AccessLog, User
from flask import request, session  # Fixed: Added missing imports
import requests  # For Geo-IP

def get_geo_ip_risk(ip):
    """Stub for your Geo-IP/impossible travel. Returns risk 0-40."""
    if ip.startswith('10.'):  # Local/trusted
        return 0, []
    try:
        geo = requests.get(f'http://ip-api.com/json/{ip}').json()
        if geo.get('country') == 'SG':  # Expected for you
            return 10, ['Foreign IP']
        return 30, ['High-risk location']
    except:
        return 20, ['Geo-IP fail']

def calculate_risk_score(user_id):
    """
    Full Zero-Trust Risk: Identity + Location/Device + Behavior.
    0-100 score. Now Flask-aware.
    """
    user = User.query.get(user_id)
    if not user:
        return 100, ['No user']

    risk_score = 0
    reasons = []

    # Your existing identity risk (~40% weight)
    identity_risk, id_reasons = calculate_identity_risk(user)
    risk_score += identity_risk * 0.4
    reasons.extend(id_reasons)

    # Location/Geo-IP (~30%)
    ip_risk, ip_reasons = get_geo_ip_risk(request.remote_addr)
    risk_score += ip_risk * 0.3
    reasons.extend(ip_reasons)

    # Device stub (~20%)
    risk_score += 10  # Baseline
    reasons.append('Device baseline (+10)')

    # Behavior (~10%) - Fixed: Now uses session safely
    last_ok = session.get('last_ok_time')
    if last_ok:
        try:
            last_ok_time = datetime.fromisoformat(last_ok)
            if (datetime.now() - last_ok_time) > timedelta(minutes=10):
                risk_score += 15
                reasons.append('Long idle (+15)')
        except ValueError:
            pass  # Invalid timestamp, ignore

    risk_score = min(int(risk_score), 100)
    return risk_score, reasons

# Your original calculate_identity_risk (unchanged)
def calculate_identity_risk(user, current_device_hash=None):
    """
    Analyzes identity factors to return a Risk Score (0-100).
    Factors:
    1. Recent Failed Logins (Brute force detection)
    2. Unusual Time of Day (e.g., 3 AM login)
    3. Role Sensitivity (Admins have higher baseline risk)
    4. New/Unknown Device (Fingerprint mismatch)
    """

    risk_score = 0
    reasons = []

    # --- Factor 1: Recent Failed Login Attempts (Last 30 mins) ---
    failed_attempts = AccessLog.query.filter_by(
        user_id=user.id, 
        action='LOGIN_FAILED'
    ).order_by(AccessLog.timestamp.desc()).limit(5).all()

    recent_failures = len(failed_attempts)
    if recent_failures > 0:
        penalty = recent_failures * 15
        risk_score += penalty
        reasons.append(f"{recent_failures} recent failed logins (+{penalty})")

    # --- Factor 2: Time of Day Analysis ---
    current_hour = datetime.now().hour
    if current_hour < 8 or current_hour > 20:
        risk_score += 20
        reasons.append(f"Login outside office hours ({current_hour}:00) (+20)")

    # --- Factor 3: Role Sensitivity ---
    if user.role == 'admin':
        risk_score += 10
        reasons.append("High-privilege role (+10)")
    elif user.role == 'manager':
        risk_score += 5
        reasons.append("Privileged role (+5)")

    if user.last_device_hash and current_device_hash:
        if user.last_device_hash != current_device_hash:
            risk_score += 30
            reasons.append("Unknown Device Detected (+30)")

    risk_score = min(risk_score, 100)
    return risk_score, reasons
