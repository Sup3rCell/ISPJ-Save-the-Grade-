from flask import request
from models import db, AccessLog
from datetime import datetime
import json
import requests
import ipaddress

def get_ip_location(ip_address):
    """
    Resolves IP address to Country using free API.
    Handles private/local IPs gracefully.
    """
    if not ip_address:
        return "Unknown"
        
    try:
        # Check for private/local IPs using standard library
        ip = ipaddress.ip_address(ip_address)
        if ip.is_private or ip.is_loopback:
            return "Local Network (Private)"
    except ValueError:
        pass # Not a valid IP, proceed to try API anyway or return Unknown

    try:
        # Using ip-api.com (free, 45req/min)
        # It returns 'fail' for reserved IPs if we missed any
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,country", timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return data.get('country', 'Unknown')
            elif data.get('message') == 'reserved range':
                return "Local Network (Reserved)"
    except Exception:
        pass
    return "Unknown"

def log_attempt(
    user_id,
    action,
    risk,
    outcome,
    email_attempt=None,
    document_id=None,
    risk_factors=None,
    action_details=None
):
    """
    Central function to log all security-relevant events to the AccessLog table.
    """
    risk_factors_payload = None
    if risk_factors:
        if isinstance(risk_factors, str):
            risk_factors_payload = risk_factors
        else:
            risk_factors_payload = json.dumps(risk_factors)

    action_details_payload = None
    if action_details:
        action_details_payload = json.dumps(action_details)

    # Get Real IP (handle Proxy/Render)
    if 'X-Forwarded-For' in request.headers:
        # X-Forwarded-For: client, proxy1, proxy2
        ip_address = request.headers['X-Forwarded-For'].split(',')[0].strip()
    else:
        ip_address = request.remote_addr

    log = AccessLog(
        user_id=user_id,
        document_id=document_id,  # New: Added optional document ID
        action=action,
        ip_address=ip_address,
        device_info=request.headers.get('User-Agent'),
        risk_score=risk,
        risk_factors=risk_factors_payload,
        action_details=action_details_payload,
        outcome=outcome,
        timestamp=datetime.utcnow()
    )

    # Log the attempted email/location detail if the login failed (user_id is None)
    if user_id is None and email_attempt:
        log.location = f"Attempted Email: {email_attempt}"
    
    # We will log Geo-IP location here once Teammate 2 implements Geo-IP lookups.
    if not log.location:
        log.location = get_ip_location(log.ip_address)
    
    
    db.session.add(log)
    db.session.commit()