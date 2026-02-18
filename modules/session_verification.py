"""
Continuous Session Verification Module
Provides continuous risk monitoring throughout user sessions
Handles session termination and restriction based on risk assessment
"""
from datetime import datetime, timedelta
import json
from flask import session, current_app
from models import db, User, SessionRiskHistory, SecurityAlert, AccessLog
from modules.risk_engine import (
    calculate_identity_risk_score,
    calculate_location_risk_score,
    calculate_action_risk_score,
    should_block_action, 
    should_require_additional_verification
)
from modules.risk_manager import RiskManager


def record_session_risk(user_id, risk_score, risk_factors=None, risk_components=None, 
                       action='periodic_check', ip_address=None, device_hash=None, location=None):
    """
    Record a risk verification check for the current session
    """
    try:
        session_id = session.get('_permanent', 'unknown')
        
        history = SessionRiskHistory(
            user_id=user_id,
            session_id=str(session_id),
            risk_score=risk_score,
            risk_factors=json.dumps(risk_factors) if risk_factors else None,
            risk_components=json.dumps(risk_components) if risk_components else None,
            action=action,
            ip_address=ip_address,
            device_hash=device_hash,
            location=location,
            verification_status='analyzing'
        )
        db.session.add(history)
        db.session.commit()
        return history
    except Exception as e:
        db.session.rollback()
        print(f"Failed to record session risk: {e}")
        return None


def get_session_risk_trend(user_id, minutes=5):
    """
    Get the risk trend for the current session over the last N minutes
    Returns: list of risk scores over time, average risk, max risk
    """
    try:
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        
        history = SessionRiskHistory.query.filter(
            SessionRiskHistory.user_id == user_id,
            SessionRiskHistory.timestamp >= cutoff_time
        ).order_by(SessionRiskHistory.timestamp.desc()).all()
        
        if not history:
            return None
        
        risk_scores = [h.risk_score for h in history]
        avg_risk = sum(risk_scores) / len(risk_scores)
        max_risk = max(risk_scores)
        min_risk = min(risk_scores)
        
        # Check for upward trend (risk increasing)
        if len(risk_scores) >= 2:
            first_recent = risk_scores[0]
            oldest = risk_scores[-1]
            trend = 'increasing' if first_recent > oldest else 'decreasing'
        else:
            trend = 'stable'
        
        return {
            'scores': risk_scores,
            'average': round(avg_risk, 2),
            'max': max_risk,
            'min': min_risk,
            'trend': trend,
            'count': len(risk_scores)
        }
    except Exception as e:
        print(f"Error calculating session risk trend: {e}")
        return None


def evaluate_session_risk_action(risk_score, trend_data=None):
    """
    Determine the action to take based on current and historical risk
    Returns: 'allow', 'restrict', or 'terminate'
    """
    # Hard block threshold
    if should_block_action(risk_score):  # >= 80
        return 'terminate'
    
    # Soft restriction threshold
    if should_require_additional_verification(risk_score):  # >= 60
        # Check if trend is getting worse
        if trend_data and trend_data.get('trend') == 'increasing':
            return 'restrict'
        return 'restrict'
    
    # If below 60, allow
    return 'allow'


def update_session_verification_status(user_id, verification_status, resolution_notes=None):
    """
    Update the most recent session verification record
    """
    try:
        latest = SessionRiskHistory.query.filter_by(
            user_id=user_id
        ).order_by(SessionRiskHistory.timestamp.desc()).first()
        
        if latest:
            latest.verification_status = verification_status
            if resolution_notes:
                latest.resolution_notes = resolution_notes
            db.session.commit()
            return latest
    except Exception as e:
        db.session.rollback()
        print(f"Failed to update session verification: {e}")
    
    return None


def create_session_security_alert(user, risk_score, risk_factors, action, ip_address=None):
    """
    Create a security alert for session-level risk events
    """
    try:
        if action == 'terminate':
            severity = 'critical'
            title = 'Session Terminated - Critical Risk'
            alert_type = 'session_terminated'
        elif action == 'restrict':
            severity = 'high'
            title = 'Session Restricted - High Risk Detected'
            alert_type = 'session_restricted'
        else:
            return None
        
        alert = SecurityAlert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=f'Continuous session verification {action}ed session for user {user.username} due to risk score {risk_score}',
            user_id=user.id,
            alert_data=json.dumps({
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'ip_address': ip_address,
                'action': action
            }),
            status='new'
        )
        db.session.add(alert)
        db.session.commit()
        return alert
    except Exception as e:
        db.session.rollback()
        print(f"Failed to create session alert: {e}")
        return None


def verify_session_continuous(user, ip_address=None, device_hash=None, location=None, action='session_check'):
    """
    Main function to verify session risk continuously
    Called periodically throughout the session
    
    Returns: {
        'risk_score': int,
        'action': 'allow'|'restrict'|'terminate',
        'risk_factors': list,
        'components': dict,
        'trend': dict (optional),
        'message': str (optional)
    }
    """
    try:
        # Calculate current risk score
        # Calculate current risk score (detectors auto-submit to RiskManager)
        calculate_identity_risk_score(user, device_hash)
        calculate_location_risk_score(user, ip_address)
        # calculate_sensitivity_risk_score(...) # Add if needed for session checks
        calculate_action_risk_score(user, action)

        # Finalize Assessment
        risk_score, breakdown = RiskManager.finalize_risk_assessment(user)
        
        # Flatten for storage (Transformation Logic)
        risk_factors = []
        components = {}
        if 'components' in breakdown:
            for k, v in breakdown['components'].items():
                components[k] = v['score']
                risk_factors.extend(v['factors'])
        
        print(f"[SESSION VERIFY] User: {user.username}, Risk Score: {risk_score}, Factors: {risk_factors}")
        
        # Record this check in history
        history = record_session_risk(
            user_id=user.id,
            risk_score=risk_score,
            risk_factors=risk_factors,
            risk_components=components,
            action=action,
            ip_address=ip_address,
            device_hash=device_hash,
            location=location
        )
        
        # Get trend data
        trend_data = get_session_risk_trend(user.id, minutes=5)
        
        # Evaluate what action to take
        verification_action = evaluate_session_risk_action(risk_score, trend_data)
        
        print(f"[SESSION VERIFY] Action determined: {verification_action} (threshold: 80 for terminate, 60 for restrict)")
        
        # Update the history record with the action
        if history:
            update_session_verification_status(user.id, verification_action)
        
        # Create alert if action is restrict or terminate
        if verification_action in ('restrict', 'terminate'):
            create_session_security_alert(user, risk_score, risk_factors, verification_action, ip_address)
        
        # Log the verification check
        try:
            log = AccessLog(
                user_id=user.id,
                action='session_verify',
                outcome='success' if verification_action == 'allow' else 'warning',
                timestamp=datetime.utcnow(),
                ip_address=ip_address,
                user_agent=None,
                risk_score=risk_score,
                risk_factors=json.dumps(risk_factors) if risk_factors else None,
                action_details=json.dumps({'verification_action': verification_action})
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Failed to log session verification: {e}")
        
        return {
            'risk_score': risk_score,
            'action': verification_action,
            'risk_factors': risk_factors,
            'components': components,
            'trend': trend_data,
            'message': _get_action_message(verification_action, risk_score)
        }
    
    except Exception as e:
        import traceback
        print(f"Error in verify_session_continuous: {e}\n{traceback.format_exc()}")
        return {
            'risk_score': 0,
            'action': 'error',
            'risk_factors': [],
            'components': {},
            'message': f'Session verification error: {str(e)}'
        }


def _get_action_message(action, risk_score):
    """Get user-friendly message for the action"""
    if action == 'terminate':
        return 'Your session has been terminated due to high security risk. Please log in again.'
    elif action == 'restrict':
        return f'Your session is restricted due to elevated risk (score: {risk_score}/100). Some features are limited.'
    elif action == 'allow':
        return f'Session verified. Risk level normal (score: {risk_score}/100).'
    else:
        return 'Session verification encountered an error.'


def cleanup_old_session_history(days=30):
    """
    Cleanup old session risk history records (optional maintenance)
    Can be called periodically by a scheduler
    """
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        deleted_count = SessionRiskHistory.query.filter(
            SessionRiskHistory.timestamp < cutoff_date
        ).delete()
        db.session.commit()
        print(f"Cleaned up {deleted_count} old session history records")
        return deleted_count
    except Exception as e:
        db.session.rollback()
        print(f"Failed to cleanup session history: {e}")
        return 0
