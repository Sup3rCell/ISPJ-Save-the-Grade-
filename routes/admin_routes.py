"""
Admin Dashboard Routes
Provides access to system logs, metrics, risk history, and honeytoken alerts
Restricted to users with 'admin' role
"""

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, abort
from flask_login import login_required, current_user
from functools import wraps
from models import db, AccessLog, User, Document, SecurityAlert, DocVersion
from datetime import datetime, timedelta
import json

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# ============================================
# ADMIN ROLE CHECK DECORATOR
# ============================================

def admin_required(f):
    """
    Decorator to ensure only admins can access routes
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if current_user.role != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# ============================================
# ADMIN DASHBOARD - MAIN PAGE
# ============================================

@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Main admin dashboard with overview statistics"""
    
    # Get organization ID
    org_id = current_user.org_id
    
    # Statistics
    total_users = User.query.filter_by(org_id=org_id).count()
    total_documents = Document.query.join(Document.owner).filter(
        User.org_id == org_id
    ).count()
    
    # Recent activity (last 24 hours) - filter by org
    last_24h = datetime.utcnow() - timedelta(hours=24)
    recent_logs = AccessLog.query.join(User).filter(
        AccessLog.timestamp >= last_24h,
        User.org_id == org_id
    ).count()
    
    # High-risk events (last 24 hours) - filter by org
    high_risk_events = AccessLog.query.join(User).filter(
        AccessLog.timestamp >= last_24h,
        AccessLog.risk_score >= 50,
        User.org_id == org_id
    ).count()
    
    # Security alerts (last 24 hours) - filter by org (only for registered users)
    security_alerts = SecurityAlert.query.join(SecurityAlert.user).filter(
        SecurityAlert.created_at >= last_24h,
        User.org_id == org_id
    ).count()
    
    # Recent impossible travel detections - filter by org
    impossible_travels = AccessLog.query.join(User).filter(
        AccessLog.timestamp >= last_24h,
        AccessLog.risk_factors.ilike('%Impossible travel%'),
        User.org_id == org_id
    ).count()
    
    # Get chart data: activity trend (last 7 days) - filter by org
    activity_trend = {}
    for i in range(6, -1, -1):
        date = datetime.utcnow().date() - timedelta(days=i)
        date_str = date.strftime('%Y-%m-%d')
        count = AccessLog.query.join(User).filter(
            db.func.date(AccessLog.timestamp) == date,
            User.org_id == org_id
        ).count()
        activity_trend[date_str] = count
    
    # Get risk score distribution - filter by org
    risk_distribution = {
        'low': AccessLog.query.join(User).filter(
            AccessLog.risk_score < 30,
            User.org_id == org_id
        ).count(),
        'medium': AccessLog.query.join(User).filter(
            AccessLog.risk_score >= 30,
            AccessLog.risk_score < 60,
            User.org_id == org_id
        ).count(),
        'high': AccessLog.query.join(User).filter(
            AccessLog.risk_score >= 60,
            AccessLog.risk_score < 80,
            User.org_id == org_id
        ).count(),
        'critical': AccessLog.query.join(User).filter(
            AccessLog.risk_score >= 80,
            User.org_id == org_id
        ).count()
    }
    
    context = {
        'total_users': total_users,
        'total_documents': total_documents,
        'recent_activity': recent_logs,
        'high_risk_events': high_risk_events,
        'security_alerts': security_alerts,
        'impossible_travels': impossible_travels,
        'activity_trend': activity_trend,
        'risk_distribution': risk_distribution
    }
    
    return render_template('admin/dashboard.html', **context)


# ============================================
# ACCESS LOGS PAGE
# ============================================

@admin_bp.route('/logs')
@login_required
@admin_required
def logs():
    """View detailed access logs with filtering options"""
    
    # Get filter parameters from query string
    user_filter = request.args.get('user', '')
    action_filter = request.args.get('action', '')
    risk_level = request.args.get('risk_level', '')
    start_date_str = request.args.get('start_date', '')
    end_date_str = request.args.get('end_date', '')
    page = request.args.get('page', 1, type=int)
    
    # Build query - filter by organization (only show logs for registered users)
    query = AccessLog.query.join(User).filter(
        User.org_id == current_user.org_id
    )
    
    # Apply filters
    if user_filter:
        query = query.filter(AccessLog.user_id == user_filter)
    
    if action_filter:
        query = query.filter(AccessLog.action.ilike(f"%{action_filter}%"))
    
    if risk_level == 'high':
        query = query.filter(AccessLog.risk_score >= 60)
    elif risk_level == 'medium':
        query = query.filter(
            AccessLog.risk_score >= 30,
            AccessLog.risk_score < 60
        )
    elif risk_level == 'low':
        query = query.filter(AccessLog.risk_score < 30)
    
    # Date range filter
    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            query = query.filter(AccessLog.timestamp >= start_date)
        except ValueError:
            pass
    
    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AccessLog.timestamp < end_date)
        except ValueError:
            pass
    
    # Order by newest first and paginate
    logs = query.order_by(AccessLog.timestamp.desc()).paginate(page=page, per_page=50)
    
    # Get unique actions for filter dropdown
    all_actions = db.session.query(AccessLog.action).distinct().all()
    actions = [a[0] for a in all_actions if a[0]]
    
    # Get all users for filter dropdown
    all_users = User.query.filter_by(org_id=current_user.org_id).all()
    
    context = {
        'logs': logs,
        'all_users': all_users,
        'all_actions': actions,
        'user_filter': user_filter,
        'action_filter': action_filter,
        'risk_level': risk_level,
        'start_date': start_date_str,
        'end_date': end_date_str
    }
    
    return render_template('admin/logs.html', **context)


# ============================================
# DOCUMENT VERSIONS PAGE
# ============================================

@admin_bp.route('/versions')
@login_required
@admin_required
def versions():
    """View document versions and their metadata"""
    
    document_filter = request.args.get('document', '')
    page = request.args.get('page', 1, type=int)
    
    query = DocVersion.query.join(Document).join(User)
    
    if document_filter:
        query = query.filter(Document.id == document_filter)
    
    # Note: Only select columns that exist in the database
    versions = query.order_by(DocVersion.created_at.desc()).paginate(page=page, per_page=30)
    
    # Get documents for filter
    documents = Document.query.join(User).filter(User.org_id == current_user.org_id).all()
    
    context = {
        'versions': versions,
        'documents': documents,
        'document_filter': document_filter
    }
    
    return render_template('admin/versions.html', **context)


# ============================================
# RISK HISTORY PAGE
# ============================================

@admin_bp.route('/risk-history')
@login_required
@admin_required
def risk_history():
    """View risk score trends and anomalies"""
    
    org_id = current_user.org_id
    days = request.args.get('days', 30, type=int)
    risk_threshold = request.args.get('threshold', 50, type=int)
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Get high-risk events - filter by org
    high_risk_logs = AccessLog.query.join(User).filter(
        AccessLog.timestamp >= start_date,
        AccessLog.risk_score >= risk_threshold,
        User.org_id == org_id
    ).order_by(AccessLog.timestamp.desc()).all()
    
    # Build risk trend data - filter by org
    risk_trend = {}
    for i in range(days-1, -1, -1):
        date = datetime.utcnow().date() - timedelta(days=i)
        date_str = date.strftime('%Y-%m-%d')
        
        avg_risk = db.session.query(db.func.avg(AccessLog.risk_score)).join(User).filter(
            db.func.date(AccessLog.timestamp) == date,
            User.org_id == org_id
        ).scalar() or 0
        
        max_risk = db.session.query(db.func.max(AccessLog.risk_score)).join(User).filter(
            db.func.date(AccessLog.timestamp) == date,
            User.org_id == org_id
        ).scalar() or 0
        
        risk_trend[date_str] = {
            'avg': round(avg_risk, 2),
            'max': max_risk
        }
    
    # Get risk factors summary
    risk_factors_summary = {}
    for log in high_risk_logs[:100]:  # Analyze last 100 high-risk events
        if log.risk_factors:
            try:
                factors = json.loads(log.risk_factors)
                if isinstance(factors, list):
                    for factor in factors:
                        risk_factors_summary[factor] = risk_factors_summary.get(factor, 0) + 1
            except:
                pass
    
    context = {
        'high_risk_logs': high_risk_logs[:100],
        'risk_trend': risk_trend,
        'risk_factors_summary': risk_factors_summary,
        'days': days,
        'threshold': risk_threshold,
        'total_events': len(high_risk_logs)
    }
    
    return render_template('admin/risk_history.html', **context)


# ============================================
# HONEYTOKEN ALERTS PAGE
# ============================================

@admin_bp.route('/honeytoken-alerts')
@login_required
@admin_required
def honeytoken_alerts():
    """View all honeytoken alerts/triggers"""
    
    org_id = current_user.org_id
    severity_filter = request.args.get('severity', '')
    page = request.args.get('page', 1, type=int)
    
    # Filter by organization (only show alerts for registered users)
    query = SecurityAlert.query.join(SecurityAlert.user).filter(
        SecurityAlert.alert_type == 'honeytoken_access',
        User.org_id == org_id
    )
    
    if severity_filter:
        query = query.filter(SecurityAlert.severity == severity_filter)
    
    alerts = query.order_by(SecurityAlert.created_at.desc()).paginate(page=page, per_page=30)
    
    # Summary statistics - filter by org
    total_alerts = SecurityAlert.query.join(SecurityAlert.user).filter(
        SecurityAlert.alert_type == 'honeytoken_access',
        User.org_id == org_id
    ).count()
    
    critical_alerts = SecurityAlert.query.join(SecurityAlert.user).filter(
        SecurityAlert.alert_type == 'honeytoken_access',
        SecurityAlert.severity == 'critical',
        User.org_id == org_id
    ).count()
    
    high_alerts = SecurityAlert.query.join(SecurityAlert.user).filter(
        SecurityAlert.alert_type == 'honeytoken_access',
        SecurityAlert.severity == 'high',
        User.org_id == org_id
    ).count()
    
    # Get alerts by status - filter by org
    last_7_days = datetime.utcnow() - timedelta(days=7)
    recent_alerts = SecurityAlert.query.join(SecurityAlert.user).filter(
        SecurityAlert.alert_type == 'honeytoken_access',
        SecurityAlert.created_at >= last_7_days,
        User.org_id == org_id
    ).count()
    
    context = {
        'alerts': alerts,
        'total_alerts': total_alerts,
        'critical_alerts': critical_alerts,
        'high_alerts': high_alerts,
        'recent_alerts': recent_alerts,
        'severity_filter': severity_filter
    }
    
    return render_template('admin/honeytoken_alerts.html', **context)


# ============================================
# RISK ENGINE TEST PAGE
# ============================================

@admin_bp.route('/test-risk')
@login_required
@admin_required
def test_risk():
    """Admin-only page to generate test risk events"""
    return render_template('admin/test_risk.html')


@admin_bp.route('/test-risk/run', methods=['POST'])
@login_required
@admin_required
def run_test_risk():
    """Create synthetic risk events for testing"""
    payload = request.get_json(silent=True) or {}
    scenario = payload.get('scenario')

    if not scenario:
        return jsonify({'status': 'error', 'error': 'Missing scenario'}), 400

    def create_log(action, risk_score, factors, outcome='success', location=None, details=None):
        log = AccessLog(
            user_id=current_user.id,
            action=action,
            outcome=outcome,
            risk_score=risk_score,
            risk_factors=json.dumps(factors),
            action_details=json.dumps(details) if details else None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string[:256] if request.user_agent else None,
            location=location
        )
        db.session.add(log)
        return log

    created = []

    if scenario == 'failed_logins':
        for _ in range(5):
            log = create_log(
                action='LOGIN_FAILED',
                risk_score=65,
                factors=['Multiple failed login attempts'],
                outcome='denied'
            )
            created.append(log)

    elif scenario == 'rapid_downloads':
        for _ in range(10):
            log = create_log(
                action='download',
                risk_score=75,
                factors=['Rapid downloads detected - possible data theft'],
                outcome='success',
                details={'test': True, 'note': 'Synthetic download'}
            )
            created.append(log)

    elif scenario == 'impossible_travel':
        location = json.dumps({
            'city': 'Test City',
            'country': 'XX',
            'latitude': 0.0,
            'longitude': 0.0
        })
        log = create_log(
            action='session_check',
            risk_score=85,
            factors=['Impossible travel detected'],
            outcome='blocked',
            location=location
        )
        created.append(log)
        # Also create a security alert for this critical event
        alert = SecurityAlert(
            alert_type='impossible_travel',
            severity='critical',
            title='Impossible Travel Detected',
            description='User accessed from impossible location - potential account compromise',
            user_id=current_user.id,
            status='new'
        )
        db.session.add(alert)

    elif scenario == 'high_risk_alert':
        log = create_log(
            action='download',
            risk_score=90,
            factors=['High risk action blocked'],
            outcome='blocked'
        )
        created.append(log)
        alert = SecurityAlert(
            alert_type='high_risk_test',
            severity='high',
            title='High Risk Test Alert',
            description='Synthetic high-risk alert for testing',
            user_id=current_user.id,
            status='new'
        )
        db.session.add(alert)

    elif scenario == 'bulk_export':
        log = create_log(
            action='export_bulk',
            risk_score=75,
            factors=['Bulk operation detected - possible data exfiltration'],
            outcome='restricted'
        )
        created.append(log)

    else:
        return jsonify({'status': 'error', 'error': 'Unknown scenario'}), 400

    db.session.commit()

    return jsonify({
        'status': 'success',
        'created': len(created)
    })


# ============================================
# API ENDPOINTS FOR DASHBOARD CHARTS
# ============================================

@admin_bp.route('/api/activity-trend')
@login_required
@admin_required
def api_activity_trend():
    """Get activity trend data for chart"""
    days = request.args.get('days', 7, type=int)
    org_id = current_user.org_id
    
    trend_data = {}
    for i in range(days-1, -1, -1):
        date = datetime.utcnow().date() - timedelta(days=i)
        date_str = date.strftime('%Y-%m-%d')
        count = AccessLog.query.join(User).filter(
            db.func.date(AccessLog.timestamp) == date,
            User.org_id == org_id
        ).count()
        trend_data[date_str] = count
    
    return jsonify(trend_data)


@admin_bp.route('/api/risk-distribution')
@login_required
@admin_required
def api_risk_distribution():
    """Get risk score distribution"""
    org_id = current_user.org_id
    
    base_query = AccessLog.query.join(User).filter(
        User.org_id == org_id
    )
    
    return jsonify({
        'low': base_query.filter(AccessLog.risk_score < 30).count(),
        'medium': base_query.filter(
            AccessLog.risk_score >= 30,
            AccessLog.risk_score < 60
        ).count(),
        'high': base_query.filter(
            AccessLog.risk_score >= 60,
            AccessLog.risk_score < 80
        ).count(),
        'critical': base_query.filter(AccessLog.risk_score >= 80).count()
    })


@admin_bp.route('/api/top-users')
@login_required
@admin_required
def api_top_users():
    """Get users with most activity"""
    top_users = db.session.query(
        User.username,
        db.func.count(AccessLog.id).label('count')
    ).join(AccessLog).filter(
        User.org_id == current_user.org_id
    ).group_by(User.id).order_by(
        db.func.count(AccessLog.id).desc()
    ).limit(10).all()
    
    return jsonify([
        {'username': username, 'activity_count': count}
        for username, count in top_users
    ])
