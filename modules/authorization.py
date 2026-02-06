from modules.risk_engine import calculate_identity_risk

def check_document_access(user, document, current_risk_score):
    """
    Central Authorization Middleware.
    Returns: 'FULL', 'VIEW_ONLY', or 'DENIED'
    """
    
    # 1. BASELINE: Owner always gets access (unless risk is critical)
    if document.owner_id == user.id:
        if current_risk_score > 80: 
            return 'VIEW_ONLY' # Even owner is restricted if compromised
        return 'FULL'

    # 2. RBAC: Admins get full access usually
    if user.role == 'admin':
        return 'FULL'

    # 3. ABAC + RISK POLICY MATRIX
    # Classification levels: 'public', 'internal', 'confidential', 'restricted'
    
    sensitivity = document.classification
    
    # SCENARIO A: Public/Internal Docs
    if sensitivity in ['public', 'internal']:
        if current_risk_score < 70:
            return 'FULL'
        else:
            return 'VIEW_ONLY'

    # SCENARIO B: Confidential/Restricted Docs
    if sensitivity in ['confidential', 'restricted']:
        # Strict Risk Check
        if current_risk_score > 50:
            return 'DENIED' # Risk too high for sensitive data
        
        # Role Check (Staff cannot see Restricted)
        if sensitivity == 'restricted' and user.role == 'staff':
            return 'DENIED'
            
        # If passed checks, enforce MFA or View Only
        return 'VIEW_ONLY' # Zero-Trust default: Least Privilege

    return 'DENIED' # Default fallback