from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User, Organization, AccessLog
from modules.risk_engine import calculate_identity_risk
from modules.location_verification import check_impossible_travel
from modules.logging import log_attempt
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

# --- LOGIN ROUTE ---
@auth_bp.route('/login', methods=['GET', 'POST'])
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
            return redirect(url_for('auth.verify_2fa')) 
        
        user.last_device_hash = current_device_hash
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
            
        # 2. Create Organization
        new_org = Organization(name=org_name)
        db.session.add(new_org)
        db.session.flush() # Flush to get ID
        
        # 3. Create Admin User linked to Org
        new_admin = User(
            username=admin_username,
            email=admin_email,
            password_hash=generate_password_hash(password),
            role='admin', # First user is Admin
            org_id=new_org.id
        )
        
        db.session.add(new_admin)
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
            
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            org_id=current_user.org_id # FORCE SAME ORG as Admin
        )
        
        db.session.add(new_user)
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
            login_user(user)
            risk = session.get('risk_score', 0)

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

            log_attempt(user.id, 'LOGIN_2FA_SUCCESS', risk, 'ALLOWED')
            return redirect(url_for('doc.dashboard'))
        else:
            flash('Invalid 2FA Code')

    return render_template('auth/two_factor.html')

# --- LOGOUT ROUTE ---
@auth_bp.route('/logout')
@login_required
def logout():
    log_attempt(current_user.id, 'LOGOUT', 0, 'SUCCESS')
    logout_user()
    session.clear() # Clear risk scores and MFA timestamps
    flash('You have been logged out.')
    return redirect(url_for('auth.login'))