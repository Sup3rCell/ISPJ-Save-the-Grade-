from flask import Blueprint

def register_blueprints(app):
    # ===== YOUR ORIGINAL BLUEPRINTS =====
    from .auth_routes import auth_bp
    from .doc_routes import doc_bp
    from .admin_routes import admin_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(doc_bp, url_prefix='/documents')
    app.register_blueprint(admin_bp)
    

    print("✅ Blueprints: Auth, Documents, SESSION")  