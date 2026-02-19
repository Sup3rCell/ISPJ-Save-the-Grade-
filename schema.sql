-- Database Schema for ISPJ-Save-the-Grade
-- Generated based on models.py

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS document_shares;
DROP TABLE IF EXISTS risk_strategies;
DROP TABLE IF EXISTS encryption_keys;
DROP TABLE IF EXISTS session_risk_history;
DROP TABLE IF EXISTS security_alerts;
DROP TABLE IF EXISTS access_logs;
DROP TABLE IF EXISTS doc_versions;
DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organizations;

SET FOREIGN_KEY_CHECKS = 1;

-- 1. Organization Model
CREATE TABLE organizations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. User Model
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(256),
    last_device_hash VARCHAR(64),
    session_token VARCHAR(64),
    role VARCHAR(20) DEFAULT 'staff',
    org_id INT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    totp_secret VARCHAR(32),
    honeytoken_seed VARCHAR(64),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_user_org FOREIGN KEY (org_id) REFERENCES organizations(id)
);

CREATE TABLE password_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_pwd_hist_user FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 3. Document Model
CREATE TABLE documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(256) NOT NULL,
    original_filename VARCHAR(256) NOT NULL,
    filepath VARCHAR(512),
    file_data LONGBLOB,
    file_size INT,
    mime_type VARCHAR(100),
    classification VARCHAR(20) DEFAULT 'internal',
    is_encrypted BOOLEAN DEFAULT FALSE,
    encryption_key TEXT,
    encryption_iv TEXT,
    is_starred BOOLEAN DEFAULT FALSE,
    share_link_token VARCHAR(64) UNIQUE,
    share_expiry DATETIME,
    has_honeytoken BOOLEAN DEFAULT FALSE,
    honeytoken_ids TEXT,
    verification_status VARCHAR(20) DEFAULT 'unverified',
    last_verified_at DATETIME,
    verification_notes TEXT,
    verification_method VARCHAR(50),
    next_verification_at DATETIME,
    verification_attempts INT DEFAULT 0,
    owner_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at DATETIME,
    CONSTRAINT fk_doc_owner FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- 4. Document Version Model
CREATE TABLE doc_versions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    document_id INT NOT NULL,
    version_number INT NOT NULL,
    file_hash VARCHAR(128),
    file_data LONGBLOB,
    file_size INT,
    encryption_key TEXT,
    encryption_iv TEXT,
    created_by INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    risk_score_snapshot INT,
    notes TEXT,
    CONSTRAINT fk_ver_doc FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    CONSTRAINT fk_ver_creator FOREIGN KEY (created_by) REFERENCES users(id)
);

-- 5. Access Log Model
CREATE TABLE access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    document_id INT,
    device_info TEXT,
    action VARCHAR(50) NOT NULL,
    action_details TEXT,
    outcome VARCHAR(20),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent VARCHAR(256),
    location VARCHAR(100),
    risk_score INT DEFAULT 0,
    risk_factors TEXT,
    is_alert BOOLEAN DEFAULT FALSE,
    alert_level VARCHAR(20),
    CONSTRAINT fk_log_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_log_doc FOREIGN KEY (document_id) REFERENCES documents(id)
);

-- 6. Security Alert Model
CREATE TABLE security_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    user_id INT,
    document_id INT,
    title VARCHAR(256) NOT NULL,
    description TEXT,
    alert_data TEXT,
    status VARCHAR(20) DEFAULT 'new',
    resolved_at DATETIME,
    resolved_by INT,
    resolution_notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_alert_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_alert_doc FOREIGN KEY (document_id) REFERENCES documents(id),
    CONSTRAINT fk_alert_resolver FOREIGN KEY (resolved_by) REFERENCES users(id)
);

-- 8. Session Risk History Model
CREATE TABLE session_risk_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_id VARCHAR(256) NOT NULL,
    risk_score INT NOT NULL,
    risk_factors TEXT,
    risk_components TEXT,
    action VARCHAR(50),
    ip_address VARCHAR(45),
    device_hash VARCHAR(64),
    location VARCHAR(100),
    verification_status VARCHAR(20) DEFAULT 'allow',
    resolution_notes TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_session_risk_user FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 9. Encryption Key Vault
CREATE TABLE encryption_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    document_id INT NOT NULL UNIQUE,
    encrypted_key TEXT NOT NULL,
    encrypted_iv TEXT NOT NULL,
    key_hash VARCHAR(128),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_accessed DATETIME,
    access_count INT DEFAULT 0,
    recovery_phrase VARCHAR(256),
    CONSTRAINT fk_enc_key_doc FOREIGN KEY (document_id) REFERENCES documents(id)
);

-- 10. Risk State Model
CREATE TABLE risk_strategies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    current_score INT DEFAULT 0,
    risk_factors TEXT DEFAULT '[]',
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_risk_state_user FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 11. Document Share Model
CREATE TABLE document_shares (
    id INT AUTO_INCREMENT PRIMARY KEY,
    document_id INT NOT NULL,
    shared_with_user_id INT NOT NULL,
    shared_by_user_id INT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_share_doc FOREIGN KEY (document_id) REFERENCES documents(id),
    CONSTRAINT fk_share_to FOREIGN KEY (shared_with_user_id) REFERENCES users(id),
    CONSTRAINT fk_share_by FOREIGN KEY (shared_by_user_id) REFERENCES users(id)
);
