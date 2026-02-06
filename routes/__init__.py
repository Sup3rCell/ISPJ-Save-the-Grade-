from flask import Blueprint

def register_blueprints(app):
    # ===== YOUR ORIGINAL BLUEPRINTS =====
    from .auth_routes import auth_bp
    from .doc_routes import doc_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(doc_bp, url_prefix='/documents')
    
    # ===== SESSION VERIFICATION =====
    from .session_routes import session_bp
    app.register_blueprint(session_bp, url_prefix='/session')
    
    print("✅ Blueprints: Auth, Documents, SESSION")  