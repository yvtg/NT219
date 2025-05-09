from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import psycopg2
from .security import hash_password, check_password
from .database import get_db_connection
from twilio.rest import Client
import pyotp
import requests
import os
import re
import logging
from psycopg2.extras import RealDictCursor

auth_bp = Blueprint('auth', __name__)

# Cấu hình Twilio
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Đăng ký
@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user
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
            - phone
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
            phone:
              type: string
              example: +1234567890
            recaptcha_response:
              type: string
              example: recaptcha-token
    responses:
      201:
        description: User registered, OTP sent to phone
      400:
        description: Invalid input or reCAPTCHA verification failed
    """
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    phone = data.get('phone')
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

    # Lưu người dùng vào PostgreSQL
    try:
        conn = get_db_connection()
        c = conn.cursor()
        hashed_password = hash_password(password)
        c.execute(
            'INSERT INTO users (username, email, password, role, verified, phone, last_ip) VALUES (%s, %s, %s, %s, %s, %s, %s)',
            (username, email, hashed_password, 'user', 0, phone, request.remote_addr)
        )
        conn.commit()

        # Gửi OTP qua SMS
        totp = pyotp.TOTP('base32secret3232')
        otp = totp.now()
        client.messages.create(
            body=f"Your OTP is {otp}",
            from_=TWILIO_PHONE_NUMBER,
            to=phone
        )
        logging.info(f"User {email} registered, OTP sent to {phone}")
        return jsonify({'message': 'User registered, OTP sent to phone'}), 201
    except psycopg2.IntegrityError:
        logging.error(f"Duplicate username or email: {email}")
        return jsonify({'message': 'Username or email already exists'}), 400
    except Exception as e:
        logging.error(f"Error registering user {email}: {str(e)}")
        return jsonify({'message': 'Registration failed'}), 500
    finally:
        conn.close()

# Xác minh OTP
@auth_bp.route('/verify_otp', methods=['POST'])
def verify_otp():
    """
    Verify OTP for user registration
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
            - otp
          properties:
            email:
              type: string
              example: johndoe@example.com
            otp:
              type: string
              example: 123456
    responses:
      200:
        description: Email verified
      400:
        description: Invalid OTP
    """
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    totp = pyotp.TOTP('base32secret3232')
    if totp.verify(otp):
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('UPDATE users SET verified = 1 WHERE email = %s', (email,))
        conn.commit()
        conn.close()
        logging.info(f"User {email} verified OTP")
        return jsonify({'message': 'Email verified'}), 200
    logging.warning(f"Invalid OTP for {email}")
    return jsonify({'message': 'Invalid OTP'}), 400

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

    if user and check_password(user['password'], password) and user['verified']:
        access_token = create_access_token(identity=email, additional_claims={'role': user['role']})
        refresh_token = create_refresh_token(identity=email)
        logging.info(f"User {email} logged in from IP {request.remote_addr}")
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
    logging.warning(f"Failed login attempt for {email} from IP {request.remote_addr}")
    return jsonify({'message': 'Invalid credentials or unverified email'}), 401

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

# MFA
@auth_bp.route('/mfa', methods=['POST'])
@jwt_required()
def mfa():
    """
    Multi-Factor Authentication
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - otp
          properties:
            otp:
              type: string
              example: 123456
    responses:
      200:
        description: MFA successful
      401:
        description: Invalid OTP
    """
    data = request.get_json()
    otp = data.get('otp')
    email = get_jwt_identity()

    totp = pyotp.TOTP('base32secret3232')
    if totp.verify(otp):
        logging.info(f"MFA successful for {email}")
        return jsonify({'message': 'MFA successful'}), 200
    logging.warning(f"Invalid MFA OTP for {email}")
    return jsonify({'message': 'Invalid OTP'}), 401