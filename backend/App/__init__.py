from flask import Flask, jsonify
from flask_jwt_extended import JWTManager, get_jwt, get_jwt_identity, jwt_required
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flasgger import Swagger
from flask_cors import CORS
from dotenv import load_dotenv
import os
from psycopg2.extras import RealDictCursor
from App.database import get_db_connection

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', 'config', '.env'))

def create_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-very-strong-secret-key')

    # Khởi tạo JWT
    jwt = JWTManager(app)

    # Cấu hình rate limiting
    app.config['RATELIMIT_KEY_FUNC'] = get_remote_address
    app.config['RATELIMIT_DEFAULTS'] = ["200 per day", "50 per hour"]
    limiter = Limiter(app)

    # Kích hoạt CORS
    CORS(app,
     origins=["http://127.0.0.1:5501"],
     supports_credentials=True,
     allow_headers=["Authorization", "Content-Type","x-csrf-token"])
    # Khởi tạo Flasgger (Swagger UI)
    app.config['SWAGGER'] = {
        'title': 'API Documentation',
        'uiversion': 3,
        'version': '1.0',
        'description': 'API for Authentication and Authorization System'
    }
    swagger = Swagger(app)

    # Đăng ký blueprints
    from .auth import auth_bp
    from .routes import routes_bp
    from .video import videos_bp
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(routes_bp, url_prefix='/api')
    app.register_blueprint(videos_bp, url_prefix='/api')
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    app.config['JWT_COOKIE_SECURE'] = False  # True nếu dùng HTTPS
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False
    return app