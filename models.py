from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy.dialects.mysql import LONGBLOB # Explicit import for MySQL

db = SQLAlchemy()

# --- 1. Organization Model ---
class Organization(db.Model):
    __tablename__ = 'organizations'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    users = db.relationship('User', backref='organization', lazy='dynamic')

# --- 2. User Model ---
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    # Device Fingerprinting
    last_device_hash = db.Column(db.String(64))
    
    # NEW: Concurrent Session Control
    # We store a token here. If the session cookie doesn't match this, log them out.
    session_token = db.Column(db.String(64))

    # RBAC Role: 'staff', 'manager', 'admin'
    role = db.Column(db.String(20), default='staff')

    # Link to Organization
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)

    # Security Fields
    is_active = db.Column(db.Boolean, default=True) # New: Soft delete/archive
    totp_secret = db.Column(db.String(32))  # For 2FA
    honeytoken_seed = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    logs = db.relationship('AccessLog', backref='user', lazy='dynamic')
    documents = db.relationship('Document', backref='owner', lazy='dynamic')

class PasswordHistory(db.Model):
    __tablename__ = 'password_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- 3. Document Model (Enhanced with Encryption Keys) ---
class Document(db.Model):
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    original_filename = db.Column(db.String(256), nullable=False)
    filepath = db.Column(db.String(512), nullable=True) # Made nullable as we might use BLOB now
    file_data = db.Column(LONGBLOB) # Explicit MySQL LONGBLOB
    file_size = db.Column(db.Integer)
    mime_type = db.Column(db.String(100))

    # Classification & Security
    classification = db.Column(db.String(20), default='internal')
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_key = db.Column(db.Text)  # Base64 encoded encryption key
    encryption_iv = db.Column(db.Text)  # Base64 encoded IV
    
    # User Preferences
    is_starred = db.Column(db.Boolean, default=False)
    
    # Sharing
    share_link_token = db.Column(db.String(64), unique=True, nullable=True)
    share_expiry = db.Column(db.DateTime, nullable=True)

    # Honeytoken tracking
    has_honeytoken = db.Column(db.Boolean, default=False)
    honeytoken_ids = db.Column(db.Text)  # JSON string of token IDs

    # Verification fields
    verification_status = db.Column(db.String(20), default='unverified')  # unverified, verified, failed
    last_verified_at = db.Column(db.DateTime, nullable=True)
    verification_notes = db.Column(db.Text, nullable=True)
    verification_method = db.Column(db.String(50), nullable=True)
    next_verification_at = db.Column(db.DateTime, nullable=True)
    verification_attempts = db.Column(db.Integer, default=0)

    # Ownership & Timestamps
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Soft delete
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)

    # Relationships
    versions = db.relationship('DocVersion', backref='document', lazy='dynamic', cascade='all, delete-orphan')
    access_logs = db.relationship('AccessLog', backref='document', lazy='dynamic')


# --- 4. Document Version Model ---
class DocVersion(db.Model):
    __tablename__ = 'doc_versions'

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    version_number = db.Column(db.Integer, nullable=False)
    file_hash = db.Column(db.String(128))
    file_data = db.Column(LONGBLOB) # Explicit MySQL LONGBLOB
    file_size = db.Column(db.Integer)

    # Encryption info for this version
    encryption_key = db.Column(db.Text)
    encryption_iv = db.Column(db.Text)

    # Metadata
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    risk_score_snapshot = db.Column(db.Integer)
    notes = db.Column(db.Text)
    
    # Relationships
    created_by_user = db.relationship('User', foreign_keys=[created_by])


# --- 5. Access Log Model (Enhanced) ---
class AccessLog(db.Model):
    __tablename__ = 'access_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=True)
    device_info = db.Column(db.Text)

    # Action details
    action = db.Column(db.String(50), nullable=False)
    action_details = db.Column(db.Text)  # JSON for additional info
    outcome = db.Column(db.String(20))  # success, denied, error

    # Context
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(256))
    location = db.Column(db.String(100))

    # Risk assessment
    risk_score = db.Column(db.Integer, default=0)
    risk_factors = db.Column(db.Text)  # JSON array of risk factors

    # Alert flag
    is_alert = db.Column(db.Boolean, default=False)
    alert_level = db.Column(db.String(20))  # low, medium, high, critical


# --- 6. Security Alert Model (New) ---
class SecurityAlert(db.Model):
    __tablename__ = 'security_alerts'

    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(50), nullable=False)  # honeytoken_access, failed_login, etc.
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical

    # Related entities
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=True)

    # Alert details
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    alert_data = db.Column(db.Text)  # JSON with additional data

    # Status
    status = db.Column(db.String(20), default='new')  # new, investigating, resolved, dismissed
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    resolution_notes = db.Column(db.Text)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id])
    document = db.relationship('Document')
    resolved_by_user = db.relationship('User', foreign_keys=[resolved_by])


# --- 7. Encryption Key Vault (New - for backup) ---
# --- 8. Session Risk History Model (New - for continuous verification) ---
class SessionRiskHistory(db.Model):
    __tablename__ = 'session_risk_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(256), nullable=False)  # Flask session ID

    # Risk tracking
    risk_score = db.Column(db.Integer, nullable=False)
    risk_factors = db.Column(db.Text)  # JSON array of risk factors
    risk_components = db.Column(db.Text)  # JSON with component breakdown

    # Session context
    action = db.Column(db.String(50))  # What triggered the check
    ip_address = db.Column(db.String(45))
    device_hash = db.Column(db.String(64))
    location = db.Column(db.String(100))

    # Verification result
    verification_status = db.Column(db.String(20), default='allow')  # allow, restrict, terminate
    resolution_notes = db.Column(db.Text)

    # Timestamps
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Relationships
    user = db.relationship('User', backref='session_risk_history')


# --- 9. Encryption Key Vault (New - for backup) ---
class EncryptionKeyVault(db.Model):
    __tablename__ = 'encryption_keys'

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False, unique=True)

    # Encrypted storage of keys (encrypted with master key)
    encrypted_key = db.Column(db.Text, nullable=False)
    encrypted_iv = db.Column(db.Text, nullable=False)
    key_hash = db.Column(db.String(128))  # For verification

    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)
    access_count = db.Column(db.Integer, default=0)

    # Recovery info
    recovery_phrase = db.Column(db.String(256))  # Optional recovery mechanism

# --- 10. Risk State Model (New - for persistent risk scoring) ---
class RiskState(db.Model):
    __tablename__ = 'risk_strategies'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    
    # Persistent Risk Score
    current_score = db.Column(db.Integer, default=0)
    
    # Active Risk Factors (JSON list)
    risk_factors = db.Column(db.Text, default='[]')
    
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user_relationship = db.relationship('User', backref=db.backref('risk_state', uselist=False))

# --- 11. Document Share Model (P2P Sharing) ---
class DocumentShare(db.Model):
    __tablename__ = 'document_shares'

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    shared_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    document = db.relationship('Document', backref='shares')
    shared_with_user = db.relationship('User', foreign_keys=[shared_with_user_id], backref='received_shares')
    shared_by_user = db.relationship('User', foreign_keys=[shared_by_user_id], backref='sent_shares')
