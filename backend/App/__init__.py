from flask import Flask
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flasgger import Swagger
from dotenv import load_dotenv
import os

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', 'config', '.env'))

def create_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-very-strong-secret-key')

    # Khởi tạo JWT
    jwt = JWTManager(app)

    # Cấu hình rate limiting thông qua app.config
    app.config['RATELIMIT_KEY_FUNC'] = get_remote_address
    app.config['RATELIMIT_DEFAULTS'] = ["200 per day", "50 per hour"]

    # Khởi tạo Limiter
    limiter = Limiter(app)

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
    app.register_blueprint(auth_bp)
    app.register_blueprint(routes_bp)

    return app