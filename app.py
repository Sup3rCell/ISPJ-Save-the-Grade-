from flask import Flask, redirect, url_for, session
from config import Config
from models import db, User
from flask_login import LoginManager
from routes import register_blueprints
from routes.admin_routes import admin_bp

def create_app():
    # 1. Initialize Flask
    app = Flask(__name__)
    
    # 2. Load Config
    app.config.from_object(Config)
    
    # 3. Initialize Extensions
    db.init_app(app)
    
    login = LoginManager(app)
    login.login_view = 'auth.login'

    @login.user_loader
    def load_user(id):
        return User.query.get(int(id))
    
    @app.context_processor
    def inject_session():
        return {'session': session}

    # 4. Register ALL Blueprints (single call!)
    register_blueprints(app)
    app.register_blueprint(admin_bp)

    @app.route('/')
    def index():
        return redirect(url_for('auth.login'))

    # 5. Create DB
    with app.app_context():
        db.create_all()

    return app

# Run ONLY create_app()
if __name__ == '__main__':
    app = create_app()
    print("🚀 Zero-Trust Gateway is running on http://127.0.0.1:5000")
    app.run(debug=True)
