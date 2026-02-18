"""
Enhanced Risk Engine Module for InfoSecurity Project
Provides advanced risk scoring and anomaly detection
Implements Zero-Trust Risk Scoring: Identity + Location + Sensitivity
"""

from datetime import datetime, timedelta
from models import AccessLog, User, Document, db
import re
import json
from collections import defaultdict
from modules.location_verification import verify_location_on_login
from modules.risk_manager import RiskManager


# ============================================
# ZERO-TRUST RISK SCORING ENGINE
# Combines Identity + Location + Sensitivity
# ============================================

def calculate_zero_trust_risk_score(user, action, document=None, ip_address=None, device_info=None):
    """
    Comprehensive Zero-Trust Risk Scoring that combines:
    1. Identity Risk (35% weight)
    2. Location Risk (35% weight)
    3. Sensitivity Risk (30% weight)
    
    Returns:
        tuple: (overall_score, risk_factors, component_scores)
    """
    if not user:
        return 0, [], {}
    
    # Calculate component scores
    identity_score, identity_factors = calculate_identity_risk_score(user, device_info)
    location_score, location_factors = calculate_location_risk_score(user, ip_address)
    sensitivity_score, sensitivity_factors = calculate_sensitivity_risk_score(document, user.role)
    
    # Action-based adjustments
    action_score, action_factors = calculate_action_risk_score(user, action)
    
    # Weighted combination
    component_scores = {
        'identity': identity_score,
        'location': location_score,
        'sensitivity': sensitivity_score,
        'action': action_score
    }
    
    # Zero-Trust weights: emphasize identity and location, sensitivity matters for what they're accessing
    overall_score = round(
        (identity_score * 0.35) +
        (location_score * 0.35) +
        (sensitivity_score * 0.25) +
        (action_score * 0.05)
    )
    
    base_score = overall_score
    print(f"[RISK ENGINE] Base weighted score: {base_score} (identity:{identity_score}, location:{location_score}, sensitivity:{sensitivity_score}, action:{action_score})")
    
    # Check for recent high-risk events (last 2 minutes) - add AFTER weighted calculation
    # This ensures inherited risk is not diluted by weighting
    recent_high_risk = AccessLog.query.filter(
        AccessLog.user_id == user.id,
        AccessLog.timestamp >= datetime.utcnow() - timedelta(minutes=2),
        AccessLog.risk_score >= 70
    ).order_by(AccessLog.timestamp.desc()).first()
    
    inherited_risk = 0
    if recent_high_risk:
        # Inherit a significant portion of the recent high risk score
        # If recent event was critical (>=80), inherit 80% (not weighted)
        # If recent event was high (70-79), inherit 60% (not weighted)
        if recent_high_risk.risk_score >= 80:
            inherited_risk = int(recent_high_risk.risk_score * 0.8)
        else:
            inherited_risk = int(recent_high_risk.risk_score * 0.6)
        
        print(f"[RISK ENGINE] Found recent high-risk event: score={recent_high_risk.risk_score}, inheriting {inherited_risk} points")
        overall_score += inherited_risk
        print(f"[RISK ENGINE] Score after inheritance: {base_score} + {inherited_risk} = {overall_score}")
        
        # Parse risk factors from the recent event
        try:
            if recent_high_risk.risk_factors:
                past_factors = json.loads(recent_high_risk.risk_factors)
                if isinstance(past_factors, list) and past_factors:
                    identity_factors.append(f"Recent high-risk event: {past_factors[0]} (score: {recent_high_risk.risk_score})")
                else:
                    identity_factors.append(f"Recent high-risk event detected (score: {recent_high_risk.risk_score})")
            else:
                identity_factors.append(f"Recent high-risk event detected (score: {recent_high_risk.risk_score})")
        except:
            identity_factors.append(f"Recent high-risk event detected (score: {recent_high_risk.risk_score})")
    
    # Cap at 100
    overall_score = min(100, max(0, overall_score))
    
    # Combine all risk factors
    risk_factors = identity_factors + location_factors + sensitivity_factors + action_factors
    
    return overall_score, risk_factors, component_scores

# Darius
def calculate_identity_risk_score(user, current_device_hash=None):
    """
    Calculate identity risk based on:
    - Failed login attempts (brute force)
    - Time of access
    - Role/privilege level
    - Device changes
    - Session anomalies
    
    Uses Reset → Add Risk → Clamp approach
    
    Returns: (risk_score, risk_factors)
    """
    # STEP 1: RESET - Start with baseline
    risk_score = 0
    risk_factors = []
    
    if not user:
        return 0, []
    
    # STEP 2: ADD RISK - Check for identity anomalies
    
    # --- Anomaly 1: Recent Failed Login Attempts (last 24 hours) ---
    failed_attempts = AccessLog.query.filter(
        AccessLog.user_id == user.id,
        AccessLog.action.like('%LOGIN%'),
        AccessLog.outcome == 'denied',
        AccessLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    if failed_attempts >= 5:
        risk_score += 40
        risk_factors.append(f"🔴 Multiple failed login attempts ({failed_attempts} in 24h) - Brute force risk")
    elif failed_attempts >= 3:
        risk_score += 25
        risk_factors.append(f"⚠️  Several failed login attempts ({failed_attempts} in 24h)")
    elif failed_attempts >= 1:
        risk_score += 10
        risk_factors.append("Recent failed login attempt")
    
    # --- Anomaly 2: Unusual Time of Access (Outside Business Hours) ---
    current_hour = datetime.utcnow().hour
    if current_hour >= 22 or current_hour <= 5:  # 10 PM - 5 AM
        risk_score += 25
        risk_factors.append(f"⚠️  Access outside business hours ({current_hour}:00, unusual pattern)")
    elif current_hour == 21 or current_hour == 6:  # 9 PM - 6 AM edges
        risk_score += 12
        risk_factors.append(f"Access during early/late hours ({current_hour}:00)")
    
    # --- Anomaly 3: High-Privilege Role (Admin/Manager) ---
    role_risk = {
        'admin': 30,      # Higher baseline for admin accounts (more attractive targets)
        'manager': 15,    # Medium baseline for managers
        'staff': 0        # No baseline for regular staff
    }
    role_base = role_risk.get(user.role, 0)
    if role_base > 0:
        risk_score += role_base
        risk_factors.append(f"High-privilege role ({user.role}) - Higher risk account")
    
    # --- Anomaly 4: Device Fingerprint Mismatch (New Device) ---
    if user.last_device_hash and current_device_hash:
        if user.last_device_hash != current_device_hash:
            risk_score += 30
            risk_factors.append("🔴 New device detected (fingerprint mismatch)")
    elif not user.last_device_hash and current_device_hash:
        risk_score += 8
        risk_factors.append("First login from this device (new baseline)")
    
    # --- Anomaly 5: Concurrent Session Attempts (Session Hijacking Detection) ---
    concurrent_sessions = AccessLog.query.filter(
        AccessLog.user_id == user.id,
        AccessLog.timestamp >= datetime.utcnow() - timedelta(minutes=5)
    ).count()
    if concurrent_sessions > 1:
        risk_score += 20
        risk_factors.append(f"⚠️  Multiple concurrent sessions detected ({concurrent_sessions}) - Possible hijacking")
    
    # STEP 3: CLAMP - Ensure score stays within 0-100 range
    final_score = min(100, max(0, risk_score))
    print(f"[RISK ENGINE] Identity risk score: {final_score} (factors: {len(risk_factors)})")
    
    # Auto-submit to Risk Manager
    RiskManager.submit_risk_component('identity', final_score, risk_factors)
    
    return final_score, risk_factors


def calculate_location_risk_score(user, current_ip):
    """
    Calculate location/geographic risk based on:
    - Impossible travel detection
    - IP reputation / ISP changes
    - Geographic anomalies
    - VPN/Proxy detection
    
    Uses the Reset → Add Risk → Clamp approach:
    1. START: risk_score = 0 (fresh baseline)
    2. ADD: Risk points for detected anomalies
    3. CLAMP: Keep within 0-100 range
    
    Returns: (risk_score, risk_factors)
    """
    # STEP 1: RESET - Start with baseline risk
    risk_score = 0
    risk_factors = []
    
    if not user or not current_ip:
        return 0, []
    
    try:
        # Use location verification module to check for impossible travel and get location data
        location_result = verify_location_on_login(user.id, current_ip)
        location_json = location_result.get('location_json')
        location_data = None
        travel_check = location_result.get('travel_check')
        
        # STEP 2: ADD RISK - Check for various location anomalies
        
        # --- Anomaly 1: Impossible Travel Detection ---
        if travel_check and travel_check.get('is_impossible'):
            risk_score += 65  # Critical risk: physically impossible to travel this far
            risk_factors.append(
                f"❌ IMPOSSIBLE TRAVEL: {travel_check.get('previous_location')} → "
                f"{travel_check.get('current_location')} "
                f"({travel_check.get('distance_km')}km in {travel_check.get('time_hours')}h, "
                f"requires {travel_check.get('required_speed_kmh')}km/h)"
            )
            print(f"[RISK ENGINE] Impossible travel detected: +65 risk")
        elif travel_check and travel_check.get('severity') == 'LOW':
            # Valid travel detected
            risk_factors.append(
                f"Normal travel: {travel_check.get('previous_location')} → "
                f"{travel_check.get('current_location')} "
                f"({travel_check.get('distance_km')}km in {travel_check.get('time_hours')}h)"
            )
        
        # Parse location data for additional checks
        if location_json:
            try:
                location_data = json.loads(location_json)
            except:
                location_data = None
        
        if location_data:
            # --- Anomaly 2: VPN/Proxy Detection ---
            current_isp = location_data.get('isp', '')
            if current_isp and ('VPN' in current_isp or 'Proxy' in current_isp or 'proxy' in current_isp.lower()):
                risk_score += 20
                risk_factors.append(f"⚠️  VPN/Proxy detected: {current_isp}")
                print(f"[RISK ENGINE] VPN/Proxy detected: +20 risk ({current_isp})")
            
            # --- Anomaly 3: ISP Change Detection ---
            last_log = AccessLog.query.filter_by(user_id=user.id).order_by(
                AccessLog.timestamp.desc()
            ).first()
            
            if last_log and last_log.location:
                try:
                    last_location = json.loads(last_log.location)
                    last_isp = last_location.get('isp', '')
                    
                    if last_isp and current_isp and last_isp != current_isp and 'VPN' not in current_isp:
                        # ISP changed but not due to VPN (already counted above)
                        risk_score += 10
                        risk_factors.append(f"ISP changed: {last_isp} → {current_isp}")
                        print(f"[RISK ENGINE] ISP changed: +10 risk")
                except:
                    pass
            
            # --- Anomaly 4: Geographic Anomaly (Rapid Country Change) ---
            if last_log and last_log.location:
                try:
                    last_location = json.loads(last_log.location)
                    last_country = last_location.get('country', '')
                    current_country = location_data.get('country', '')
                    
                    if last_country and current_country and last_country != current_country:
                        time_since_last = datetime.utcnow() - last_log.timestamp
                        
                        # Country change is suspicious if it's rapid but still physically possible
                        if time_since_last < timedelta(hours=12):
                            risk_score += 15
                            hours = time_since_last.total_seconds() / 3600
                            risk_factors.append(
                                f"Geographic anomaly: {last_country} → {current_country} in {hours:.1f}h"
                            )
                            print(f"[RISK ENGINE] Geographic anomaly: +15 risk")
                except:
                    pass
        
        # --- Anomaly 5: First Login (New IP Baseline) ---
        if not travel_check or travel_check.get('details') == 'First login detected':
            risk_score += 5
            risk_factors.append("First login from this IP (new baseline)")
            print(f"[RISK ENGINE] First login from new IP: +5 risk")
        elif travel_check and 'Unable' in travel_check.get('details', ''):
            # Location data unavailable
            risk_score += 5
            risk_factors.append("Location data unavailable (using fallback verification)")
            print(f"[RISK ENGINE] Location unavailable: +5 risk")
        
    except Exception as e:
        print(f"[RISK ENGINE] Error in location risk calculation: {e}")
        
        # Fallback: Simple IP change detection
        last_log = AccessLog.query.filter_by(user_id=user.id).order_by(
            AccessLog.timestamp.desc()
        ).first()
        
        if last_log and last_log.ip_address and last_log.ip_address != current_ip:
            time_diff = datetime.utcnow() - last_log.timestamp
            if time_diff < timedelta(hours=1):
                risk_score += 20
                risk_factors.append(f"Rapid IP change detected (potential account compromise)")
                print(f"[RISK ENGINE] Rapid IP change: +20 risk")
            else:
                risk_score += 5
                risk_factors.append("IP address changed")
                print(f"[RISK ENGINE] IP changed: +5 risk")
    
    # STEP 3: CLAMP - Ensure score stays within 0-100 range
    final_score = min(100, max(0, risk_score))
    print(f"[RISK ENGINE] Location risk score: {final_score} (factors: {len(risk_factors)})")
    
    # Auto-submit to Risk Manager
    RiskManager.submit_risk_component('location', final_score, risk_factors)
    
    return final_score, risk_factors


def calculate_sensitivity_risk_score(document, user_role='staff'):
    """
    Calculate sensitivity risk based on:
    - Document classification level
    - User role vs document sensitivity
    - Data ownership
    - Encryption status
    
    Uses Reset → Add Risk → Clamp approach
    
    Returns: (risk_score, risk_factors)
    """
    # STEP 1: RESET - Start with baseline
    risk_score = 0
    risk_factors = []
    
    if not document:
        return 0, []
    
    # STEP 2: ADD RISK - Check for sensitivity anomalies
    
    # --- Anomaly 1: Document Classification Level ---
    classification_risk = {
        'public': 0,
        'internal': 10,
        'confidential': 20,
        'restricted': 35,
        'top_secret': 55
    }
    
    doc_risk = classification_risk.get(document.classification, 15)
    risk_score += doc_risk
    
    if doc_risk > 10:
        risk_factors.append(f"Document Classification: {document.classification.upper()} (+{doc_risk})")
    
    # --- Anomaly 2: Privilege Mismatch (Staff accessing high-classification docs) ---
    if document.classification in ['restricted', 'top_secret']:
        if user_role == 'staff':
            risk_score += 25
            risk_factors.append(f"🔴 Staff accessing {document.classification} document - Privilege mismatch (+25)")
        elif user_role == 'manager':
            risk_score += 12
            risk_factors.append(f"Manager accessing {document.classification} document (+12)")
    
    # --- Anomaly 3: Unencrypted Sensitive Document ---
    if not document.is_encrypted and document.classification in ['confidential', 'restricted', 'top_secret']:
        risk_score += 18
        risk_factors.append(f"⚠️  Accessing unencrypted {document.classification} document (+18)")
    
    # --- Anomaly 4: Honeytoken Presence (Tracking Enabled) ---
    if document.has_honeytoken:
        risk_score += 8
        risk_factors.append("Document contains honeytokens - Activity tracking enabled (+8)")
    
    # STEP 3: CLAMP - Ensure score stays within 0-100 range
    final_score = min(100, max(0, risk_score))
    print(f"[RISK ENGINE] Sensitivity risk score: {final_score} (factors: {len(risk_factors)})")
    
    # Auto-submit to Risk Manager
    RiskManager.submit_risk_component('sensitivity', final_score, risk_factors)
    
    return final_score, risk_factors


def calculate_action_risk_score(user, action):
    """
    Calculate risk based on the action being performed:
    - Privilege escalation attempts
    - Bulk operations / data exfiltration patterns
    - Administrative actions
    - Rare actions
    
    Uses Reset → Add Risk → Clamp approach
    
    Returns: (risk_score, risk_factors)
    """
    # STEP 1: RESET - Start with baseline
    risk_score = 0
    risk_factors = []
    
    if not user or not action:
        return 0, []
    
    action_lower = action.lower()
    
    # STEP 2: ADD RISK - Check for risky action patterns
    
    # --- Anomaly 1: Privilege Escalation Attempts ---
    admin_actions = ['create_user', 'delete_user', 'modify_roles', 'system_config', 'reset_password']
    if user.role == 'staff' and any(adm_action in action_lower for adm_action in admin_actions):
        risk_score += 45
        risk_factors.append(f"🔴 Staff attempting admin action ({action}) - Privilege escalation (+45)")
    elif user.role == 'manager' and any(adm_action in action_lower for adm_action in admin_actions):
        risk_score += 18
        risk_factors.append(f"Manager attempting admin action ({action}) (+18)")
    
    # --- Anomaly 2: Bulk Operations (Data Exfiltration Pattern) ---
    bulk_keywords = ['bulk', 'batch', 'export', 'multiple', 'all']
    if any(keyword in action_lower for keyword in bulk_keywords):
        last_hour_count = AccessLog.query.filter(
            AccessLog.user_id == user.id,
            AccessLog.timestamp >= datetime.utcnow() - timedelta(hours=1)
        ).count()
        
        if last_hour_count > 50:
            risk_score += 28
            risk_factors.append(f"Bulk operation with excessive activity ({last_hour_count} actions/hr) (+28)")
        else:
            risk_score += 12
            risk_factors.append(f"Bulk operation detected (+12)")
    
    # --- Anomaly 3: Rapid Downloads (Data Theft Pattern) ---
    if 'download' in action_lower or 'export' in action_lower or 'decrypt' in action_lower:
        recent_downloads = AccessLog.query.filter(
            AccessLog.user_id == user.id,
            AccessLog.action.in_(['download', 'export', 'decrypt']),
            AccessLog.timestamp >= datetime.utcnow() - timedelta(minutes=10)
        ).count()
        
        if recent_downloads > 10:
            risk_score += 35
            risk_factors.append(f"🔴 Rapid downloads ({recent_downloads} in 10min) - Possible data theft (+35)")
        elif recent_downloads > 5:
            risk_score += 18
            risk_factors.append(f"Multiple downloads in short time ({recent_downloads} in 10min) (+18)")
    
    # --- Anomaly 4: Document Deletion ---
    if 'delete' in action_lower:
        risk_score += 8
        risk_factors.append("Document deletion action (+8)")
    
    # STEP 3: CLAMP - Ensure score stays within 0-100 range
    final_score = min(100, max(0, risk_score))
    if final_score > 0:
        print(f"[RISK ENGINE] Action risk score: {final_score} (action: {action}, factors: {len(risk_factors)})")
    
    # Auto-submit to Risk Manager
    RiskManager.submit_risk_component('action', final_score, risk_factors)
    
    return final_score, risk_factors


# ============================================
# BACKWARD COMPATIBILITY - LEGACY SCORING
# ============================================

def calculate_advanced_risk_score(user, action, document=None, ip_address=None, device_info=None):
    """
    Advanced risk calculation (legacy interface)
    Now uses the Zero-Trust Risk Scoring Engine internally

    Args:
        user: User object
        action: Action being performed
        document: Optional Document object
        ip_address: Optional IP address
        device_info: Optional device information

    Returns:
        tuple: (risk_score, risk_factors)
    """
    # Use the new Zero-Trust scoring engine
    score, factors, components = calculate_zero_trust_risk_score(
        user=user,
        action=action,
        document=document,
        ip_address=ip_address,
        device_info=device_info
    )
    
    return score, factors


# ============================================
# LEGACY FUNCTIONS - REMOVED (Unused)
# ============================================
# The following functions were removed as they were not used anywhere in the application:
# - calculate_time_risk()
# - calculate_authentication_risk()
# - calculate_document_risk()
# - calculate_geographic_risk()
# - calculate_frequency_risk()
# - calculate_device_risk()
# - calculate_privilege_risk()
# - calculate_bulk_operation_risk()
# These were part of an earlier risk calculation approach and have been superseded by
# the more comprehensive calculate_zero_trust_risk_score() function.


# ============================================
# RISK-BASED ACTIONS
# ============================================

def should_require_additional_verification(risk_score):
    """Determine if additional verification is needed based on risk"""
    return risk_score >= 60


def should_block_action(risk_score):
    """Determine if action should be blocked based on risk"""
    return risk_score >= 80


# ============================================
# RISK REDUCTION METHODS
# ============================================

def reduce_risk_on_2fa_success(user):
    """
    Reset risk score to 0 when user successfully passes 2FA verification
    
    2FA verification is a strong identity confirmation, so we completely reset risk.
    This allows users to recover from high-risk states after proving their identity.
    
    Risk Reset:
    - Resets to 0 (clean slate after identity verification)
    - Risk is completely cleared
    
    Returns:
        dict: {success, original_risk, reduced_risk, reduction_reason}
    """
    if not user:
        print("[RISK ENGINE] 2FA reset: No user provided")
        return {'success': False, 'reason': 'No user provided'}
    
    try:
        # Look for the most recent high-risk access log that triggered 2FA requirement
        recent_high_risk = AccessLog.query.filter(
            AccessLog.user_id == user.id,
            AccessLog.action.in_(['LOGIN', 'STEP_UP_MFA']),
            AccessLog.timestamp >= datetime.utcnow() - timedelta(minutes=10)
        ).order_by(AccessLog.timestamp.desc()).first()
        
        original_risk = 0
        if recent_high_risk:
            original_risk = recent_high_risk.risk_score
        
        # RESET to 0 - strong identity verification clears all risk
        reset_risk = 0
        
        print(f"[RISK ENGINE] ✅ 2FA Success: Identity verified. Risk RESET from {original_risk} → {reset_risk}")
        
        return {
            'success': True,
            'original_risk': original_risk,
            'reduced_risk': reset_risk,
            'reduction_reason': f'✅ 2FA Verification Success (Risk Reset to 0)',
            'user_id': user.id
        }
    
    except Exception as e:
        print(f"[RISK ENGINE] 2FA reduction error: {e}")
        return {'success': False, 'reason': str(e)}
