from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

# Initialize the database instance
db = SQLAlchemy()

# --- 1. Organization Model (NEW) ---
class Organization(db.Model):
    __tablename__ = 'organizations'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship: One Org has Many Users
    users = db.relationship('User', backref='organization', lazy='dynamic')

# --- 2. User Model (UPDATED) ---
class User(UserMixin, db.Model): 
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False) # Global uniqueness for simplicity
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    
    # RBAC Role: 'staff', 'manager', 'admin'
    role = db.Column(db.String(20), default='staff')
    
    # Link to Organization (NEW)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    
    # Security Fields
    totp_secret = db.Column(db.String(32)) # For 2FA
    honeytoken_seed = db.Column(db.String(64))

    # Device Fingerprinting
    last_device_hash = db.Column(db.String(64))
    
    # Relationships
    logs = db.relationship('AccessLog', backref='user', lazy='dynamic')

# ... (Document, DocVersion, AccessLog remain the same, maybe add org_id to Document if needed later) ...
class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(128), nullable=False)
    classification = db.Column(db.String(20), default='internal')
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    versions = db.relationship('DocVersion', backref='document', lazy='dynamic')

class DocVersion(db.Model):
    __tablename__ = 'doc_versions'
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'))
    version_number = db.Column(db.Integer, nullable=False)
    storage_path = db.Column(db.String(256), nullable=False)
    file_hash = db.Column(db.String(128))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    risk_score_snapshot = db.Column(db.Integer)

class AccessLog(db.Model):
    __tablename__ = 'access_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # nullable for anonymous attempts
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(50))
    ip_address = db.Column(db.String(45))
    device_info = db.Column(db.String(256))
    location = db.Column(db.String(100))
    # NEW FIELDS FOR GEO/IP + IMPOSSIBLE TRAVEL
    latitude = db.Column(db.Float)           # DOUBLE in MySQL
    longitude = db.Column(db.Float)
    travel_distance_km = db.Column(db.Float)
    travel_speed_kmh = db.Column(db.Float)
    impossible_travel_flag = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Integer)
    outcome = db.Column(db.String(20))