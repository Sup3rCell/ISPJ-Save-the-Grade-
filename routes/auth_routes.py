from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User, Organization, PasswordHistory, AccessLog
from modules.risk_engine import (
    calculate_identity_risk_score, 
    calculate_location_risk_score, 
    calculate_sensitivity_risk_score, 
    calculate_action_risk_score,
    reduce_risk_on_2fa_success
)
from modules.risk_manager import RiskManager
from modules.logging import log_attempt
from modules.security_utils import check_password_strength, check_pwned_password, generate_magic_link, verify_magic_link_token, generate_session_token
from extensions import limiter, oauth 
import pyotp
import qrcode
import io
import base64
import hashlib
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)

@auth_bp.before_app_request
def check_concurrent_session():
    """
    Middleware to enforce single-session policy.
    """
    if current_user.is_authenticated:
        if current_user.session_token and session.get('session_token') != current_user.session_token:
            logout_user()
            session.clear()
            flash("You have been logged out because a new session was started on another device.")
            return redirect(url_for('auth.login'))

# --- GOOGLE LOGIN ROUTES ---

@auth_bp.route('/login/google')
def google_login():
    # This generates the URL .../auth/google/callback
    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

# FIXED: Removed the extra '/auth' prefix. The blueprint provides it automatically.
@auth_bp.route('/google/callback')
def google_callback():
    try:
        token = oauth.google.authorize_access_token()
        user_info = token.get('userinfo')
        email = user_info.get('email')
    except Exception as e:
        flash("Google Login Failed.")
        return redirect(url_for('auth.login'))
        
    # 1. Check if user exists (Invite-Only Architecture)
    user = User.query.filter_by(email=email).first()
    
    if not user:
        log_attempt(None, 'LOGIN_SSO_FAILED_NO_ACCOUNT', 100, 'DENIED', email_attempt=email)
        flash("No account found. Please ask your administrator to create your account.")
        return redirect(url_for('auth.login'))
        
    # 2. Device Fingerprinting
    ua_string = request.headers.get('User-Agent', '')
    current_device_hash = hashlib.sha256(ua_string.encode()).hexdigest()
    
    # 3. Risk Analysis (Zero-Trust via RiskManager Aggregation)
    # Calculate components using the specialized engine (they auto-submit to RiskManager)
    calculate_identity_risk_score(user, current_device_hash)
    calculate_location_risk_score(user, request.remote_addr)
    # calculate_sensitivity_risk_score(None, user.role) # No document, skipping or can call with None
    calculate_sensitivity_risk_score(None, user.role)
    calculate_action_risk_score(user, 'login_sso')

    # Finalize Assessment
    risk_score, breakdown = RiskManager.finalize_risk_assessment(user)
    
    # Extract factors and components for session/logs
    risk_factors = []
    components = {}
    for k, v in breakdown['components'].items():
        components[k] = v['score']
        risk_factors.extend(v['factors'])
    
    # 4. Enforce 2FA / High Risk Check
    if risk_score > 60 or user.totp_secret:
        session['pre_2fa_user_id'] = user.id
        session['risk_score'] = risk_score
        session['risk_factors'] = risk_factors
        session['risk_components'] = components
        session['auth_method'] = 'google' 
        return redirect(url_for('auth.verify_2fa')) 

    # 5. Success
    new_token = generate_session_token()
    user.session_token = new_token
    session['session_token'] = new_token
    user.last_device_hash = current_device_hash
    db.session.commit()
    
    login_user(user)
    log_attempt(
        user.id,
        'LOGIN_SSO_SUCCESS',
        risk_score,
        'ALLOWED',
        risk_factors=risk_factors,
        action_details={'components': components, 'auth_method': 'google'}
    )
    
    flash("Successfully logged in via Google!")
    return redirect(url_for('doc.dashboard'))

# --- STANDARD LOGIN ROUTES ---

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            if user:
                # Update persistent risk score
                new_score = RiskManager.update_risk(user.id, 10, "Failed Login Attempt")
                print(f"[AUTH] Increased risk for {user.username} to {new_score}")
                
            log_attempt(None, 'LOGIN_FAILED', 50, 'DENIED', email_attempt=email)
            flash('Invalid credentials') 
            return redirect(url_for('auth.login'))

        # Device Fingerprinting
        ua_string = request.headers.get('User-Agent', '')
        current_device_hash = hashlib.sha256(ua_string.encode()).hexdigest()

        # Risk Analysis (Zero-Trust via RiskManager Aggregation)
        calculate_identity_risk_score(user, current_device_hash)
        calculate_location_risk_score(user, request.remote_addr)
        calculate_sensitivity_risk_score(None, user.role)
        calculate_action_risk_score(user, 'login_password')

        risk_score, breakdown = RiskManager.finalize_risk_assessment(user)

        # Extract factors and components for session/logs
        risk_factors = []
        components = {}
        for k, v in breakdown['components'].items():
            components[k] = v['score']
            risk_factors.extend(v['factors'])
        
        # 2FA Check
        if risk_score > 60 or user.totp_secret:
            session['pre_2fa_user_id'] = user.id
            session['risk_score'] = risk_score
            session['risk_factors'] = risk_factors
            session['risk_components'] = components
            session['auth_method'] = 'password'
            return redirect(url_for('auth.verify_2fa')) 

        # Success
        user.last_device_hash = current_device_hash
        new_token = generate_session_token()
        user.session_token = new_token
        session['session_token'] = new_token
        
        db.session.commit()

        login_user(user)
        log_attempt(
            user.id,
            'LOGIN_SUCCESS',
            risk_score,
            'ALLOWED',
            risk_factors=risk_factors,
            action_details={'components': components, 'auth_method': 'password'}
        )
        return redirect(url_for('doc.dashboard'))

    return render_template('auth/login.html')

@auth_bp.route('/magic-login-request', methods=['POST'])
@limiter.limit("3 per minute")
def magic_login_request():
    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()
    
    if user:
        link_token = generate_magic_link(email)
        full_link = url_for('auth.magic_login_verify', token=link_token, _external=True)
        print(f"\n[MAGIC LINK] for {email}: {full_link}\n")
        flash("Magic link sent! (Check Server Console)")
    else:
        flash("If an account exists, a link has been sent.")
        
    return redirect(url_for('auth.login'))

@auth_bp.route('/magic-login-verify/<token>')
def magic_login_verify(token):
    email = verify_magic_link_token(token)
    if not email:
        flash("Invalid or expired magic link.")
        return redirect(url_for('auth.login'))
        
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.")
        return redirect(url_for('auth.login'))
        
    ua_string = request.headers.get('User-Agent', '')
    current_device_hash = hashlib.sha256(ua_string.encode()).hexdigest() if ua_string else None

    # Risk Analysis
    calculate_identity_risk_score(user, current_device_hash)
    calculate_location_risk_score(user, request.remote_addr)
    calculate_sensitivity_risk_score(None, user.role)
    calculate_action_risk_score(user, 'login_magic')

    risk_score, breakdown = RiskManager.finalize_risk_assessment(user)

    # Extract factors and components
    risk_factors = []
    components = {}
    for k, v in breakdown['components'].items():
        components[k] = v['score']
        risk_factors.extend(v['factors'])

    new_token = generate_session_token()
    user.session_token = new_token
    session['session_token'] = new_token
    
    db.session.commit()
    login_user(user)
    log_attempt(
        user.id,
        'LOGIN_MAGIC_LINK',
        risk_score,
        'ALLOWED',
        risk_factors=risk_factors,
        action_details={'components': components, 'auth_method': 'magic_link'}
    )
    
    flash("Logged in via Magic Link!")
    return redirect(url_for('doc.dashboard'))

@auth_bp.route('/register-org', methods=['GET', 'POST'])
def register_org():
    if request.method == 'POST':
        org_name = request.form.get('org_name')
        admin_username = request.form.get('username')
        admin_email = request.form.get('email')
        password = request.form.get('password')
        
        if Organization.query.filter_by(name=org_name).first():
            flash('Organization name already registered')
            return redirect(url_for('auth.register_org'))
            
        if User.query.filter_by(email=admin_email).first():
            flash('Email already registered')
            return redirect(url_for('auth.register_org'))
        
        is_strong, msg = check_password_strength(password, [org_name, admin_username, admin_email])
        if not is_strong:
            flash(f"Weak Password: {msg}")
            return redirect(url_for('auth.register_org'))
            
        if check_pwned_password(password):
            flash("Security Alert: This password has been exposed in a data breach.")
            return redirect(url_for('auth.register_org'))
            
        new_org = Organization(name=org_name)
        db.session.add(new_org)
        db.session.flush()
        
        pw_hash = generate_password_hash(password)
        new_admin = User(
            username=admin_username,
            email=admin_email,
            password_hash=pw_hash,
            role='admin',
            org_id=new_org.id
        )
        db.session.add(new_admin)
        db.session.flush()
        
        pwd_hist = PasswordHistory(user_id=new_admin.id, password_hash=pw_hash)
        db.session.add(pwd_hist)
        
        db.session.commit()
        
        flash('Organization registered! Please login as Admin.')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/register_org.html')

@auth_bp.route('/create-user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        flash("Unauthorized: Only Admins can create users.")
        return redirect(url_for('doc.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('auth.create_user'))
            
        is_strong, msg = check_password_strength(password, [username, email])
        if not is_strong:
            flash(f"Weak Password: {msg}")
            return redirect(url_for('auth.create_user'))

        pw_hash = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            password_hash=pw_hash,
            role=role,
            org_id=current_user.org_id
        )
        db.session.add(new_user)
        db.session.flush()
        
        pwd_hist = PasswordHistory(user_id=new_user.id, password_hash=pw_hash)
        db.session.add(pwd_hist)
        
        db.session.commit()
        flash(f'User {username} created successfully!')
        return redirect(url_for('doc.dashboard'))
    
    return render_template('auth/create_user_internal.html')

@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if request.method == 'POST':
        otp_token = request.form.get('otp_token')
        secret = session.get('temp_totp_secret')
        
        if not secret:
            flash("Session expired.")
            return redirect(url_for('auth.setup_2fa'))

        totp = pyotp.TOTP(secret)
        if totp.verify(otp_token):
            current_user.totp_secret = secret
            db.session.commit()
            session['last_mfa_time'] = datetime.utcnow().timestamp()
            flash("2FA Enabled Successfully!")
            return redirect(url_for('doc.dashboard'))
        else:
            flash("Invalid Code.")

    secret = pyotp.random_base32()
    session['temp_totp_secret'] = secret

    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email, 
        issuer_name="ZeroTrustGateway"
    )

    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf)
    img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template('auth/setup_2fa.html', qr_code=img_b64, secret=secret)

@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        otp_token = request.form.get('otp_token')
        user = User.query.get(user_id)
        
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(otp_token):
            # ✅ 2FA Successfully Verified - Reset Risk Score to 0
            risk_reduction = reduce_risk_on_2fa_success(user)
            
            # 🧹 Clear old high-risk logs that would be inherited
            # This prevents the pre-2FA login attempt from haunting the user after successful verification
            AccessLog.query.filter(
                AccessLog.user_id == user.id,
                AccessLog.timestamp >= datetime.utcnow() - timedelta(minutes=10),
                AccessLog.risk_score >= 70
            ).update({AccessLog.risk_score: 0})
            db.session.commit()
            
            # Concurrent Session Handling for MFA Login
            new_token = generate_session_token()
            user.session_token = new_token
            session['session_token'] = new_token
            db.session.commit()
            
            login_user(user)
            
            # Set risk to 0 after successful 2FA
            risk = 0
            risk_factors = []
            risk_components = {}
            auth_method = session.get('auth_method', 'password') # e.g. 'google' or 'password'
            
            # Add 2FA success to risk factors for tracking
            if risk_reduction['success']:
                risk_factors.append(risk_reduction['reduction_reason'])
            
            # Clear previous risk session data
            session.pop('pre_2fa_user_id', None)
            session.pop('risk_factors', None)
            session.pop('risk_components', None)
            session['last_mfa_time'] = datetime.utcnow().timestamp()
            # Set clean risk score in session
            session['risk_score'] = 0
            
            next_url = session.get('next_url')
            if next_url:
                session.pop('next_url', None)
                log_attempt(
                    user.id,
                    'STEP_UP_MFA_SUCCESS',
                    risk,
                    'ALLOWED',
                    risk_factors=risk_factors,
                    action_details={'components': risk_components, 'auth_method': auth_method}
                )
                return redirect(next_url)
            
            # Differentiate logs based on how they started (SSO vs Password)
            action = 'LOGIN_SSO_2FA_SUCCESS' if auth_method == 'google' else 'LOGIN_2FA_SUCCESS'
            log_attempt(
                user.id,
                action,
                risk,
                'ALLOWED',
                risk_factors=risk_factors,
                action_details={'components': risk_components, 'auth_method': auth_method}
            )
            return redirect(url_for('doc.dashboard'))
        else:
            flash('Invalid 2FA Code')
            
    return render_template('auth/two_factor.html')

@auth_bp.route('/logout')
@login_required
def logout():
    log_attempt(current_user.id, 'LOGOUT', 0, 'SUCCESS')
    current_user.session_token = None
    db.session.commit()
    logout_user()
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('auth.login'))


# ============================================
# CONTINUOUS SESSION VERIFICATION (GLOBAL)
# ============================================

@auth_bp.route('/session/verify', methods=['POST'])
@login_required
def verify_session_global():
    """
    Global session verification endpoint - checks risk throughout entire session
    This is called continuously by ALL pages (not just document viewer)
    Can be called from any page in the application
    """
    from flask import jsonify
    from modules.session_verification import verify_session_continuous
    import hashlib
    
    try:
        # Get device hash from user agent
        ua_string = request.headers.get('User-Agent', '')
        device_hash = hashlib.sha256(ua_string.encode()).hexdigest() if ua_string else None
        
        # Get optional location info from request
        location = request.headers.get('X-Geoip-Country', None)
        
        # Optional force mode for testing (debug only)
        force = None
        try:
            payload = request.get_json(silent=True) or {}
            force = payload.get('force')
        except Exception:
            force = request.args.get('force')
        
        # If force mode in debug, override verification
        if force and current_app.debug:
            if force == 'terminate':
                action = 'terminate'
            elif force == 'restrict':
                action = 'restrict'
            else:
                action = 'allow'
            
            result = {
                'risk_score': 85 if force == 'terminate' else (70 if force == 'restrict' else 25),
                'action': action,
                'risk_factors': ['FORCED_TEST'],
                'components': {'test': True},
                'message': f'TEST MODE: {action}'
            }
        else:
            # Normal verification flow
            result = verify_session_continuous(
                user=current_user,
                ip_address=request.remote_addr,
                device_hash=device_hash,
                location=location,
                action='session_continuous_check'
            )
        
        # Determine HTTP status code
        status_code = 200
        if result.get('action') == 'terminate':
            status_code = 403
        elif result.get('action') == 'restrict':
            status_code = 429
        
        return jsonify(result), status_code
    
    except Exception as e:
        import traceback
        print(f"Session verification error:\n{traceback.format_exc()}")
        payload = {
            'risk_score': 0,
            'action': 'error',
            'risk_factors': [],
            'components': {},
            'message': 'Session verification encountered an error'
        }
        return jsonify(payload), 500


@auth_bp.route('/api/session/history', methods=['GET'])
@login_required
def get_session_history():
    """
    Get session risk history for the current user (last 5 minutes)
    Useful for debugging and monitoring during the session
    """
    from flask import jsonify
    from modules.session_verification import get_session_risk_trend
    from datetime import timedelta
    
    try:
        minutes = request.args.get('minutes', 5, type=int)
        minutes = max(1, min(minutes, 60))  # Limit to 1-60 minutes
        
        trend = get_session_risk_trend(current_user.id, minutes=minutes)
        
        if trend:
            return jsonify({
                'status': 'success',
                'trend': trend,
                'period_minutes': minutes
            }), 200
        else:
            return jsonify({
                'status': 'success',
                'trend': None,
                'message': 'No session history available yet'
            }), 200
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500
