from flask import Blueprint, jsonify, session
from datetime import datetime 
from modules.session_verification import verify_session_risk

session_bp = Blueprint('session', __name__)

@session_bp.route('/verify_session', methods=['POST'])
def verify_session():
    result = verify_session_risk()
    print(f"🔍 SESSION CHECK: {result}")  # Terminal proof
    if result['action'] == 'allow':
        session['last_ok_time'] = datetime.now().isoformat()
    return jsonify(result)