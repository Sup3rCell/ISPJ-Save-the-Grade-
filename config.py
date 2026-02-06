import os
import ssl
from dotenv import load_dotenv
import ipinfo

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

# === IPinfo configuration ===
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN")
ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN)
# ============================

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-fallback-key'

    # 1. Get the URL from the environment
    db_url = os.environ.get('DATABASE_URL')

    if db_url:
        # 2. FIX 1: Automatically convert 'mysql://' to 'mysql+pymysql://'
        if db_url.startswith('mysql://'):
            db_url = db_url.replace('mysql://', 'mysql+pymysql://', 1)
            
        # 3. FIX 2: Remove 'ssl-mode=REQUIRED' (Causes TypeError in PyMySQL)
        # We will handle SSL via connect_args below instead
        db_url = db_url.replace('?ssl-mode=REQUIRED', '')
        db_url = db_url.replace('&ssl-mode=REQUIRED', '')

    # 4. Apply the URL logic
    SQLALCHEMY_DATABASE_URI = db_url or 'sqlite:///' + os.path.join(basedir, 'zero_trust_gateway.db')

    # 5. Cloud SQL Optimization & SSL Context
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 280,
        "pool_pre_ping": True,
        # This tells PyMySQL to use SSL (Required by Aiven) without crashing on the 'ssl-mode' keyword
        "connect_args": {
            "ssl": {
                "check_hostname": False,
                "verify_mode": ssl.CERT_NONE
            }
        }
    }

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(basedir, 'documents_store')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024