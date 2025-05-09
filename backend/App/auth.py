from flask import Blueprint, request, jsonify, url_for
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import psycopg2
from .security import hash_password, check_password
from .database import get_db_connection
from psycopg2.extras import RealDictCursor
import smtplib
from email.mime.text import MIMEText
import requests
import os
import re
import logging
import uuid

auth_bp = Blueprint('auth', __name__)

# Hàm gửi email xác thực
def send_verification_email(email, verification_token):
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT'))
    smtp_username = os.getenv('SMTP_USERNAME')
    smtp_password = os.getenv('SMTP_PASSWORD')
    email_from = os.getenv('EMAIL_FROM')

    # Tạo liên kết xác minh
    verification_link = f"http://localhost:8000/api/verify_email?token={verification_token}&email={email}"

    # Nội dung email
    subject = "Xác minh email của bạn"
    body = f"""
    Xin chào,

    Cảm ơn bạn đã đăng ký! Vui lòng nhấp vào liên kết dưới đây để xác minh email của bạn:

    {verification_link}

    Nếu bạn không đăng ký, vui lòng bỏ qua email này.

    Trân trọng,
    Đội ngũ Netflix
    """
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = email_from
    msg['To'] = email

    # Gửi email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(email_from, email, msg.as_string())
        logging.info(f"Verification email sent to {email}")
    except Exception as e:
        logging.error(f"Failed to send email to {email}: {str(e)}")
        raise

# Đăng ký
@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user and send verification email
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - username
            - email
            - password
            - recaptcha_response
          properties:
            username:
              type: string
              example: johndoe
            email:
              type: string
              example: johndoe@example.com
            password:
              type: string
              example: Password123!
            recaptcha_response:
              type: string
              example: recaptcha-token
    responses:
      201:
        description: User registered, verification email sent
      400:
        description: Invalid input or reCAPTCHA verification failed
    """
    data = request.get_json()
    username = data.get('username')  # Ánh xạ từ fullname
    email = data.get('email')
    password = data.get('password')
    recaptcha_response = data.get('recaptcha_response')

    # Kiểm tra reCAPTCHA v3
    recaptcha_secret = os.getenv('RECAPTCHA_SECRET_KEY')
    recaptcha_verify = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={'secret': recaptcha_secret, 'response': recaptcha_response}
    ).json()
    if not recaptcha_verify['success'] or recaptcha_verify['score'] < 0.5:
        return jsonify({'message': 'reCAPTCHA verification failed'}), 400

    # Kiểm tra định dạng email
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        return jsonify({'message': 'Invalid email'}), 400

    # Tạo token xác minh
    verification_token = str(uuid.uuid4())

    # Lưu người dùng vào PostgreSQL
    try:
        conn = get_db_connection()
        c = conn.cursor()
        hashed_password = hash_password(password)
        c.execute(
            'INSERT INTO users (username, email, password, role, verified, last_ip) VALUES (%s, %s, %s, %s, %s, %s)',
            (username, email, hashed_password, 'user', 0, request.remote_addr)
        )
        # Lưu token xác minh tạm thời (cần bảng mới hoặc cột mới)
        c.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token TEXT')
        c.execute('UPDATE users SET verification_token = %s WHERE email = %s', (verification_token, email))
        conn.commit()

        # Gửi email xác thực
        send_verification_email(email, verification_token)
        logging.info(f"User {email} registered, verification email sent")
        return jsonify({'message': 'User registered, please check your email to verify'}), 201
    except psycopg2.IntegrityError:
        logging.error(f"Duplicate username or email: {email}")
        return jsonify({'message': 'Username or email already exists'}), 400
    except Exception as e:
        logging.error(f"Error registering user {email}: {str(e)}")
        return jsonify({'message': 'Registration failed'}), 500
    finally:
        conn.close()

# Xác minh email
@auth_bp.route('/verify_email', methods=['GET'])
def verify_email():
    """
    Verify user email using token
    ---
    tags:
      - Authentication
    parameters:
      - name: token
        in: query
        type: string
        required: true
      - name: email
        in: query
        type: string
        required: true
    responses:
      200:
        description: Email verified
      400:
        description: Invalid token or email
    """
    email = request.args.get('email')
    token = request.args.get('token')

    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute('SELECT verification_token FROM users WHERE email = %s AND verified = 0', (email,))
    user = c.fetchone()

    if user and user['verification_token'] == token:
        c.execute('UPDATE users SET verified = 1, verification_token = NULL WHERE email = %s', (email,))
        conn.commit()
        conn.close()
        logging.info(f"User {email} verified email")
        return jsonify({'message': 'Email verified successfully'}), 200
    else:
        conn.close()
        logging.warning(f"Invalid verification token for {email}")
        return jsonify({'message': 'Invalid token or email'}), 400

# Đăng nhập
@auth_bp.route('/login', methods=['POST'])
def login():
    """
    User login
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
              example: johndoe@example.com
            password:
              type: string
              example: Password123!
    responses:
      200:
        description: Login successful, returns access and refresh tokens
      401:
        description: Invalid credentials or unverified email
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute('SELECT * FROM users WHERE email = %s', (email,))
    user = c.fetchone()
    conn.close()

    if not user:
        logging.warning(f"Failed login attempt for {email}: User not found")
        return jsonify({'message': 'Invalid credentials'}), 401
    if not user['verified']:
        logging.warning(f"Failed login attempt for {email}: Email not verified")
        return jsonify({'message': 'Please verify your email before logging in'}), 401
    if check_password(user['password'], password):
        access_token = create_access_token(identity=email, additional_claims={'role': user['role']})
        refresh_token = create_refresh_token(identity=email)
        logging.info(f"User {email} logged in from IP {request.remote_addr}")
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
    logging.warning(f"Failed login attempt for {email} from IP {request.remote_addr}")
    return jsonify({'message': 'Invalid credentials'}), 401

# Làm mới token
@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh access token
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    responses:
      200:
        description: New access token generated
    """
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    logging.info(f"Token refreshed for {current_user}")
    return jsonify({'access_token': new_access_token}), 200
@auth_bp.route('/check_session', methods=['GET'])
@jwt_required()
def check_session():
    """
    Check user session
    ---
    tags:
      - User
    security:
      - Bearer: []
    responses:
      200:
        description: Session details
      401:
        description: Unauthorized
    """
    current_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    email = get_jwt_identity()

    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute('SELECT last_ip FROM users WHERE email = %s', (email,))
    result = c.fetchone()
    last_ip = result['last_ip'] if result else None
    conn.close()

    if last_ip and last_ip != current_ip:
        logging.warning(f"Suspicious session for {email}: IP changed from {last_ip} to {current_ip}")

    return jsonify({'ip': current_ip, 'user_agent': user_agent, 'email': email}), 200