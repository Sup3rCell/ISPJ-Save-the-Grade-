import requests
import hashlib
import secrets
from zxcvbn import zxcvbn
from flask import url_for, current_app
from itsdangerous import URLSafeTimedSerializer

def check_password_strength(password, user_inputs=[]):
    """
    Uses zxcvbn to calculate entropy.
    user_inputs: list of strings (like username, email) to check against.
    Returns: (is_strong, feedback_message)
    """
    results = zxcvbn(password, user_inputs=user_inputs)
    score = results['score'] # 0-4
    
    if score < 3:
        feedback = results['feedback']['warning'] or "Password is too weak."
        suggestions = " ".join(results['feedback']['suggestions'])
        return False, f"{feedback} {suggestions}"
    
    return True, "Strong"

def check_pwned_password(password):
    """
    Checks HaveIBeenPwned API (k-Anonymity model).
    We send only the first 5 chars of the SHA1 hash.
    Returns: True if pwned (found in breach), False otherwise.
    """
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code != 200:
            return False # Fail open if API is down
        
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return True # FOUND!
        return False
    except:
        return False

def generate_magic_link(email):
    """
    Generates a secure, signed token for passwordless login.
    """
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='magic-login-salt')

def verify_magic_link_token(token, expiration=300):
    """
    Verifies the token. Valid for 5 minutes (300s).
    """
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='magic-login-salt', max_age=expiration)
        return email
    except:
        return None

def generate_session_token():
    return secrets.token_hex(16)