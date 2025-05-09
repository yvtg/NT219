from App import create_app
from App.database import init_db
from App.logging_conf import setup_logging
from dotenv import load_dotenv
import os
from flask_restx import Api  # Import Flask-RESTX APIpp
from App.routes import routes_bp
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config', '.env'))

if __name__ == '__main__':
    init_db()  
    setup_logging()

    # Khởi tạo ứng dụng Flask
    app = create_app()

    # Tạo đối tượng API từ Flask-RESTX
    api = Api(app, doc='/docs')  # Tạo giao diện Swagger UI tại /docs

    # Chạy ứng dụng Flask
    app.run(debug=True, host='0.0.0.0', port=8000)