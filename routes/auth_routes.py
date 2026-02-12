from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User, Organization, PasswordHistory, AccessLog
from modules.risk_engine import calculate_identity_risk
from modules.location_verification import check_impossible_travel
from modules.logging import log_attempt
from modules.security_utils import check_password_strength, check_pwned_password, generate_magic_link, verify_magic_link_token, generate_session_token
from extentions import limiter, oauth
import pyotp
import qrcode
import io
import base64
from config import ipinfo_handler
from datetime import datetime
import hashlib


auth_bp = Blueprint('auth', __name__)

def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr

def geoip_lookup(ip):
    # Localhost fallback so testing works
    if ip.startswith("127.") or ip == "localhost":
        # Example: Singapore
        country = "SG"
        city = "Singapore"
        lat = 1.3521
        lon = 103.8198
        location_str = f"{city}, {country}"
        print("DEBUG: using localhost fallback location", location_str, lat, lon)
        return country, city, lat, lon, location_str

    try:
        details = ipinfo_handler.getDetails(ip)
        print("DEBUG: IPinfo details:", details.all)
        country = details.country
        city = details.city
        loc = details.loc  # "lat,lon"
        lat = lon = None
        if loc:
            lat_str, lon_str = loc.split(",")
            lat = float(lat_str)
            lon = float(lon_str)
        location_str = f"{city}, {country}" if city and country else (country or "Unknown")
        return country, city, lat, lon, location_str
    except Exception as e:
        print("DEBUG: geoip error", e)
        return None, None, None, None, None


# --- CONCURRENT SESSION MIDDLEWARE ---
@auth_bp.before_app_request
def check_concurrent_session():
    """
    Runs before every request. Checks if the user's session token 
    matches the one in the DB. If not, they were logged out elsewhere.
    """
    if current_user.is_authenticated:
        # If user has a token in DB but session is missing/different
        if current_user.session_token and session.get('session_token') != current_user.session_token:
            logout_user()
            session.clear()
            flash("You have been logged out because a new session was started on another device.")
            return redirect(url_for('auth.login'))


# --- GOOGLE LOGIN ROUTES ---
@auth_bp.route('/login/google')
def google_login():
    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

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
    
    # 3. Risk Analysis
    risk_score, risk_reasons = calculate_identity_risk(user, current_device_hash)
    
    # 4. CRITICAL FIX: Enforce 2FA / High Risk Check
    # Even with Google Auth, if they have TOTP enabled or High Risk, we challenge them.
    if risk_score > 60 or user.totp_secret:
        session['pre_2fa_user_id'] = user.id
        session['risk_score'] = risk_score
        # Store that they passed the first factor (Google)
        session['auth_method'] = 'google' 
        return redirect(url_for('auth.verify_2fa')) 

    # 5. Success (Low Risk & No 2FA) -> Log them in
    new_token = generate_session_token()
    user.session_token = new_token
    session['session_token'] = new_token
    user.last_device_hash = current_device_hash
    db.session.commit()
    
    login_user(user)
    log_attempt(user.id, 'LOGIN_SSO_SUCCESS', risk_score, 'ALLOWED')
    
    flash("Successfully logged in via Google!")
    return redirect(url_for('doc.dashboard'))

# --- STANDARD LOGIN ROUTES ---
# --- LOGIN ROUTE ---
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Rate Limit: Brute Force Protection
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            log_attempt(None, 'LOGIN_FAILED', 50, 'DENIED', email_attempt=email)
            flash('Invalid credentials') 
            return redirect(url_for('auth.login'))

        # Device Fingerprinting
        ua_string = request.headers.get('User-Agent', '')
        current_device_hash = hashlib.sha256(ua_string.encode()).hexdigest()

        # Risk Analysis
        risk_score, risk_reasons = calculate_identity_risk(user, current_device_hash)
        
        if risk_score > 60 or user.totp_secret:
            session['pre_2fa_user_id'] = user.id
            session['risk_score'] = risk_score
            session['auth_method'] = 'password'
            return redirect(url_for('auth.verify_2fa')) 
        
        user.last_device_hash = current_device_hash

        # Generate new session token (Invalidates other sessions)
        new_token = generate_session_token()
        user.session_token = new_token
        session['session_token'] = new_token # Save to browser cookie

        db.session.commit()

        login_user(user)
        log_attempt(user.id, 'LOGIN_SUCCESS', risk_score, 'ALLOWED')
        ip = get_client_ip()
        country, city, lat, lon, location_str = geoip_lookup(ip)
        now = datetime.utcnow()
        travel_distance_km = None
        travel_speed_kmh = None
        impossible_flag = False

        if lat is not None and lon is not None:
            travel_distance_km, travel_speed_kmh, impossible_flag = check_impossible_travel(
                user.id, lat, lon, now
            )
        if impossible_flag:
            risk_score += 40

        access_log = AccessLog(
            user_id=user.id,
            document_id=None,
            timestamp=now,
            action="LOGIN",
            ip_address=ip,
            device_info=request.user_agent.string,
            location=location_str,
            latitude=lat,
            longitude=lon,
            travel_distance_km=travel_distance_km,
            travel_speed_kmh=travel_speed_kmh,
            impossible_travel_flag=impossible_flag,
            risk_score=risk_score,   # <-- use risk_score here
            outcome="ALLOWED",
        )

        db.session.add(access_log)
        db.session.commit()
        return redirect(url_for('doc.dashboard'))

    return render_template('auth/login.html')

# --- MAGIC LINK REQUEST ---
@auth_bp.route('/magic-login-request', methods=['POST'])
@limiter.limit("3 per minute")
def magic_login_request():
    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()
    
    if user:
        link_token = generate_magic_link(email)
        full_link = url_for('auth.magic_login_verify', token=link_token, _external=True)
        
        # In production, send email. For prototype, print to console.
        print(f"\n[MAGIC LINK] for {email}: {full_link}\n")
        flash("Magic link sent! (Check Server Console)")
    else:
        # Don't reveal user existence
        flash("If an account exists, a link has been sent.")
        
    return redirect(url_for('auth.login'))

# --- MAGIC LINK VERIFY ---
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
        
    # Valid Magic Link - Log them in
    new_token = generate_session_token()
    user.session_token = new_token
    session['session_token'] = new_token
    
    db.session.commit()
    login_user(user)
    log_attempt(user.id, 'LOGIN_MAGIC_LINK', 0, 'ALLOWED')
    
    flash("Logged in via Magic Link!")
    return redirect(url_for('doc.dashboard'))

# --- PUBLIC ROUTE: REGISTER ORGANIZATION ---
# This replaces the old 'register' route.
@auth_bp.route('/register-org', methods=['GET', 'POST'])
def register_org():
    if request.method == 'POST':
        org_name = request.form.get('org_name')
        admin_username = request.form.get('username')
        admin_email = request.form.get('email')
        password = request.form.get('password')
        
        # 1. Check uniqueness
        if Organization.query.filter_by(name=org_name).first():
            flash('Organization name already registered')
            return redirect(url_for('auth.register_org'))
            
        if User.query.filter_by(email=admin_email).first():
            flash('Email already registered')
            return redirect(url_for('auth.register_org'))
        
        # 2. Check Password Strength (zxcvbn)
        is_strong, msg = check_password_strength(password, [org_name, admin_username, admin_email])
        if not is_strong:
            flash(f"Weak Password: {msg}")
            return redirect(url_for('auth.register_org'))
        
        # 3. Check Breached Passwords (HaveIBeenPwned)
        if check_pwned_password(password):
            flash("Security Alert: This password has been exposed in a data breach. Please choose a different one.")
            return redirect(url_for('auth.register_org'))
            
        # 2. Create Organization
        new_org = Organization(name=org_name)
        db.session.add(new_org)
        db.session.flush() # Flush to get ID
        
        # 3. Create Admin User linked to Org
        pw_hash = generate_password_hash(password)
        new_admin = User(
            username=admin_username,
            email=admin_email,
            password_hash=pw_hash,
            role='admin', # First user is Admin
            org_id=new_org.id
        )
        
        db.session.add(new_admin)

        db.session.flush()
        
        # 5. Save Password History
        pwd_hist = PasswordHistory(user_id=new_admin.id, password_hash=pw_hash)
        db.session.add(pwd_hist)

        db.session.commit()
        
        flash('Organization registered! Please login as Admin.')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/register_org.html')

# --- INTERNAL ROUTE: CREATE USER (ADMIN ONLY) ---
# Only Admins can access this to add Staff/Managers to their Org.
@auth_bp.route('/create-user', methods=['GET', 'POST'])
@login_required
def create_user():
    # 1. Check Permission
    if current_user.role != 'admin':
        flash("Unauthorized: Only Admins can create users.")
        return redirect(url_for('doc.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password') # Admin sets initial password
        role = request.form.get('role') # Admin chooses: 'staff' or 'manager'
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('auth.create_user'))
        
        # Basic complexity check for admin-created passwords
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
            org_id=current_user.org_id # FORCE SAME ORG as Admin
        )
        
        db.session.add(new_user)
        db.session.flush() # Flush to get ID

        # Save password history for new user
        pwd_hist = PasswordHistory(user_id=new_user.id, password_hash=pw_hash)
        db.session.add(pwd_hist)

        db.session.commit()
        
        flash(f'User {username} created successfully!')
        return redirect(url_for('doc.dashboard'))
    
    # Needs a template for internal user creation
    return render_template('auth/create_user_internal.html')

# --- MFA SETUP ROUTE ---
@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if request.method == 'POST':
        otp_token = request.form.get('otp_token')
        secret = session.get('temp_totp_secret')
        
        if not secret:
            flash("Session expired, try again.")
            return redirect(url_for('auth.setup_2fa'))

        totp = pyotp.TOTP(secret)
        if totp.verify(otp_token):
            current_user.totp_secret = secret
            db.session.commit()

            # Set MFA timestamp on setup too
            session['last_mfa_time'] = datetime.utcnow().timestamp()

            flash("2FA Enabled Successfully!")
            return redirect(url_for('doc.dashboard'))
        else:
            flash("Invalid Code. Scan again.")

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

# --- MFA VERIFY ROUTE ---
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

            # Concurrent Session Handling for MFA Login
            new_token = generate_session_token()
            user.session_token = new_token
            session['session_token'] = new_token
            db.session.commit()

            login_user(user)
            risk = session.get('risk_score', 0)
            auth_method = session.get('auth_method', 'password') # e.g. 'google' or 'password'


            ip = get_client_ip()
            country, city, lat, lon, location_str = geoip_lookup(ip)
            now = datetime.utcnow()
            travel_distance_km = None
            travel_speed_kmh = None
            impossible_flag = False

            if lat is not None and lon is not None:
                travel_distance_km, travel_speed_kmh, impossible_flag = check_impossible_travel(
                    user.id, lat, lon, now
                )

            if impossible_flag:
                risk += 40

            access_log = AccessLog(
                user_id=user.id,
                document_id=None,
                timestamp=now,
                action="LOGIN_2FA",
                ip_address=ip,
                device_info=request.user_agent.string,
                location=location_str,
                latitude=lat,
                longitude=lon,
                travel_distance_km=travel_distance_km,
                travel_speed_kmh=travel_speed_kmh,
                impossible_travel_flag=impossible_flag,
                risk_score=risk,
                outcome="ALLOWED",
            )

            db.session.add(access_log)
            db.session.commit()
            session.pop('pre_2fa_user_id', None)

            # Record the timestamp of this successful MFA
            session['last_mfa_time'] = datetime.utcnow().timestamp()
            
            # Check for Step-Up Redirect (Returning to document download)
            next_url = session.get('next_url')
            if next_url:
                session.pop('next_url', None)
                log_attempt(user.id, 'STEP_UP_MFA_SUCCESS', risk, 'ALLOWED')
                return redirect(next_url)

            # Differentiate logs based on how they started (SSO vs Password)
            action = 'LOGIN_SSO_2FA_SUCCESS' if auth_method == 'google' else 'LOGIN_2FA_SUCCESS'
            log_attempt(user.id, action, risk, 'ALLOWED')
            return redirect(url_for('doc.dashboard'))
        else:
            flash('Invalid 2FA Code')

    return render_template('auth/two_factor.html')

# --- LOGOUT ROUTE ---
@auth_bp.route('/logout')
@login_required
def logout():
    log_attempt(current_user.id, 'LOGOUT', 0, 'SUCCESS')

    # Clear session token from DB to allow clean fresh login
    current_user.session_token = None
    db.session.commit()

    logout_user()
    session.clear() # Clear risk scores and MFA timestamps
    flash('You have been logged out.')
    return redirect(url_for('auth.login'))