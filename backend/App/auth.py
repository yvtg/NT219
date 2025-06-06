import hashlib
import secrets
from dotenv import load_dotenv
from flask import Blueprint, json, redirect, request, jsonify, make_response
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt, get_jwt_identity, jwt_required, verify_jwt_in_request
from flask_jwt_extended.exceptions import NoAuthorizationError
from itsdangerous import URLSafeTimedSerializer
import psycopg2
from psycopg2.extras import RealDictCursor
from .security import hash_password, check_password,sanitize_input, generate_csrf_token, set_csrf_cookie
from .database import get_db_connection
import smtplib
from email.mime.text import MIMEText
import os
import re
import logging
import uuid
from datetime import datetime, timedelta
from collections import defaultdict
import pyotp
import qrcode
import io
import base64
import redis
import requests
from flask_jwt_extended import JWTManager
from flask_jwt_extended import get_jti

jwt = JWTManager()

load_dotenv(dotenv_path='D:\\NT219\\NT219\\backend\\config\\.env')

redis_client = redis.Redis(host='localhost', port=6379, db=0)
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')
print(RECAPTCHA_SECRET_KEY)
RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

auth_bp = Blueprint('auth', __name__)

# Store IP-based request counts
request_counts = defaultdict(int)
request_timestamps = defaultdict(list)
csrf_tokens = {}

def generate_csrf_token():
    return secrets.token_hex(32)

def set_csrf_cookie(response, token):
    response.set_cookie(
        'csrf_token', 
        token, 
        httponly=False, 
        secure=False,  # Set to False for localhost development
        samesite='Lax', 
        max_age=3600
    )
    return response
def get_device_fingerprint(request):
    user_agent = request.headers.get('User-Agent', '')
    accept_language = request.headers.get('Accept-Language', '')
    fingerprint = hashlib.sha256(f"{user_agent}:{accept_language}".encode()).hexdigest()
    return fingerprint

def verify_device(email, fingerprint):
    """Kiểm tra và lưu fingerprint thiết bị."""
    redis_key = f"device:{email}"
    known_devices = redis_client.get(redis_key)
    if known_devices:
        known_devices = json.loads(known_devices)
        if fingerprint not in known_devices:
            return False
    else:
        known_devices = [fingerprint]
        redis_client.setex(redis_key, 30*24*3600, json.dumps(known_devices))
    return True

def send_device_verification_email(email, fingerprint):
    """Gửi email xác minh thiết bị lạ."""
    ts = URLSafeTimedSerializer(os.getenv("SECRET_KEY"))
    token = ts.dumps({"email": email, "fingerprint": fingerprint}, salt='device-verify')
    verify_link = f"http://localhost:8000/api/auth/verify-device?token={token}"
    msg = MIMEText(f"New device detected. Verify it here: {verify_link}\nLink expires in 10 minutes.")
    msg['Subject'] = "Verify New Device"
    msg['From'] = os.getenv('EMAIL_FROM')
    msg['To'] = email

    try:
        with smtplib.SMTP(os.getenv('SMTP_SERVER'), int(os.getenv('SMTP_PORT'))) as server:
            server.starttls()
            server.login(os.getenv('SMTP_USERNAME'), os.getenv('SMTP_PASSWORD'))
            server.sendmail(os.getenv('EMAIL_FROM'), email, msg.as_string())
        logging.info(f"Device verification email sent to {email}")
    except Exception as e:
        logging.error(f"Failed to send device verification email to {email}: {str(e)}")
        raise

@auth_bp.route('/get-csrf-token', methods=['GET'])
def get_csrf_token():
    """
    Get CSRF token
    ---
    responses:
      200:
        description: Returns a CSRF token
    """
    csrf_token = generate_csrf_token()
    
    # Store token with timestamp for validation
    csrf_tokens[csrf_token] = datetime.now() + timedelta(hours=1)
    
    # Clean up expired tokens
    current_time = datetime.now()
    expired_tokens = [token for token, expiry in csrf_tokens.items() if expiry < current_time]
    for token in expired_tokens:
        csrf_tokens.pop(token, None)
    
    response = make_response(jsonify({'message': 'CSRF token generated'}))
    response = set_csrf_cookie(response, csrf_token)
    return response

# Middleware để kiểm tra CSRF token cho các yêu cầu POST
def check_csrf_token():
    if request.method in ['POST', 'PATCH', 'PUT', 'DELETE']:
        csrf_token = request.headers.get('X-CSRF-Token')
        cookie_csrf = request.cookies.get('csrf_token')
        
        # For development: log the tokens to help debug
        print(f"Request CSRF token: {csrf_token}")
        print(f"Cookie CSRF token: {cookie_csrf}")
        
        # During development, we'll be more lenient with CSRF
        if not csrf_token:
            logging.warning(f"No CSRF token in headers for request from {request.remote_addr}")
            return None
            
        if not cookie_csrf:
            logging.warning(f"No CSRF token in cookies for request from {request.remote_addr}")
            return None
            
        if csrf_token != cookie_csrf:
            logging.warning(f"CSRF token mismatch for request from {request.remote_addr}")
            return jsonify({'message': 'CSRF token invalid'}), 403
    return None

# Áp dụng CSRF check cho tất cả endpoint POST
@auth_bp.before_request
def before_request():
    # Skip CSRF check for certain endpoints during development
    if request.endpoint in ['auth.get_csrf_token', 'auth.login', 'auth.register']:
        return None
        
    csrf_error = check_csrf_token()
    if csrf_error:
        return csrf_error
        
    # Thêm CSP header cho tất cả response
    response = make_response()
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Expect-CT'] = 'max-age=86400, enforce'
    return None

# Hàm gửi email xác thực
def send_verification_email(email, verification_token):
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT'))
    smtp_username = os.getenv('SMTP_USERNAME')
    smtp_password = os.getenv('SMTP_PASSWORD')
    email_from = os.getenv('EMAIL_FROM')

    # Escape email và token để ngăn XSS trong email body
    email = sanitize_input(email)
    verification_token = sanitize_input(verification_token)
    verification_link = f"http://localhost:8000/api/auth/verify_email?token={verification_token}&email={email}"

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

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(email_from, email, msg.as_string())
        logging.info(f"Verification email sent to {email}")
    except Exception as e:
        logging.error(f"Failed to send email to {email}: {str(e)}")
        raise

# Hàm kiểm tra giới hạn số lần đăng ký từ cùng IP
def check_rate_limit(ip, key_prefix='register', max_attempts=5, expire=300):
    key = f"{key_prefix}:{ip}"
    attempts = redis_client.get(key)
    if attempts and int(attempts) >= max_attempts:
        return False
    if not attempts:
        redis_client.setex(key, expire, 1)
    else:
        redis_client.incr(key)
    return True

def is_strong_password(password, username, email):
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    if username.lower() in password.lower() or email.lower() in password.lower():
        return False, "Password must not contain username or email"
    common_patterns = ["password", "1234", "qwerty"]
    if any(pattern in password.lower() for pattern in common_patterns):
        return False, "Password contains common patterns"
    return True, ""

def verify_recaptcha(recaptcha_response):
    """
    Hàm xác thực reCAPTCHA phiên bản cuối cùng, có gửi kèm IP.
    """
    if not recaptcha_response:
        logging.warning("verify_recaptcha được gọi nhưng không có recaptcha_response token.")
        return False

    # 2. Chuẩn bị dữ liệu để gửi đến Google
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': recaptcha_response,
        'remoteip': request.remote_addr  # <-- THAY ĐỔI QUAN TRỌNG NHẤT
    }
    
    logging.info(f"Gửi yêu cầu xác thực reCAPTCHA cho IP: {request.remote_addr}")

    # 3. Gửi request và bắt mọi loại lỗi
    try:
        response = requests.post(RECAPTCHA_VERIFY_URL, data=payload, timeout=5)
        response.raise_for_status()
        
        result = response.json()
        logging.info(f"Phản hồi từ Google reCAPTCHA API: {result}")

        if result.get('success'):
            logging.info("Xác thực reCAPTCHA thành công!")
            return True
        else:
            error_codes = result.get('error-codes', [])
            logging.error(f"Xác thực reCAPTCHA thất bại với mã lỗi: {error_codes}")
            return False

    except requests.exceptions.RequestException as e:
        logging.error(f"Lỗi khi gửi request đến Google reCAPTCHA API: {e}")
        return False
    except Exception as e:
        logging.error(f"Lỗi không xác định trong hàm verify_recaptcha: {e}")
        return False
def check_if_password_pwned(password):
    sha1_password=hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    prefix,suffix = sha1_password[:5],sha1_password[5:]

    url=f'https://api.pwnedpasswords.com/range/{prefix}'
    try:
        response=request.get(url)
        response.raise_for_status()
    except:
        logging.error(f"Cound not found to HDBP API : {e}")
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)     
    return 0
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
    responses:
      201:
        description: User registered, verification email sent
      400:
        description: Invalid input or rate limit exceeded
    """
    data = request.get_json()
    username = sanitize_input(data.get('username'))
    email = sanitize_input(data.get('email'))
    password = data.get('password')

    if not all([username, email, password]):
        return jsonify({'message': 'Missing required fields'}), 400

    is_strong, message = is_strong_password(password, username, email)
    if not is_strong:
        return jsonify({'message': message}), 400
    is_password_pwned=check_if_password_pwned(password)
    if is_password_pwned:
        return jsonify({'message': 'Password has been compromised'}), 400
    ip = request.remote_addr

    if not check_rate_limit(ip, 'register'):
        return jsonify({'message': 'Too many registration attempts. Please try again later.'}), 400

    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        return jsonify({'message': 'Invalid email'}), 400

    verification_token = generate_csrf_token()

    try:
        conn = get_db_connection()
        c = conn.cursor()
        hashed_password = hash_password(password)
        c.execute(
            'INSERT INTO users (username, email, password, role, verified, last_ip, verification_token) '
            'VALUES (%s, %s, %s, %s, %s, %s, %s)',
            (username, email, hashed_password, 'user', 0, ip, verification_token)
        )
        conn.commit()

        send_verification_email(email, verification_token)
        logging.info(f"User {email} registered, verification email sent")
        return jsonify({
            'message': 'User registered, please check your email to verify. Consider enabling 2FA after verification.'
        }), 201
    except psycopg2.IntegrityError:
        logging.error(f"Duplicate username or email: {email}")
        return jsonify({'message': 'Username or email already exists'}), 400
    except Exception as e:
        logging.error(f"Error registering user {email}: {str(e)}")
        return jsonify({'message': 'Registration failed'}), 500
    finally:
        conn.close()

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
    email = sanitize_input(request.args.get('email'))
    token = sanitize_input(request.args.get('token'))

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


@auth_bp.route('/enable-2fa', methods=['POST'])
@jwt_required()
def enable_2fa():
    """
    Kích hoạt 2FA cho người dùng
    ---
    tags:
      - Authentication
    responses:
      200:
        description: 2FA enabled successfully
        content:
          application/json:
            example:
              message: 2FA enabled, scan the QR code with your authenticator app
              qr_code: data:image/png;base64,...
              secret: JBSWY3DPEHPK3PXP
      400:
        description: User not found, not verified, or 2FA already enabled
      500:
        description: Server error
    """
    email = get_jwt_identity()

    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT verified, is_2fa_enabled FROM users WHERE email = %s', (email,))
        user = c.fetchone()
        if not user or not user['verified']:
            return jsonify({'message': 'User not found or not verified'}), 400
        if user.get('is_2fa_enabled'):
            return jsonify({'message': '2FA is already enabled'}), 400

        totp_secret = pyotp.random_base32()
        c.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT')
        c.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_2fa_enabled BOOLEAN DEFAULT FALSE')
        c.execute('UPDATE users SET totp_secret = %s, is_2fa_enabled = TRUE WHERE email = %s', (totp_secret, email))
        conn.commit()

        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=email, issuer_name='Netflix')
        qr = qrcode.QRCode()
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        logging.info(f"2FA enabled for {email}")
        response = make_response(jsonify({
            'message': '2FA enabled, scan the QR code with your authenticator app',
            'qr_code': f'data:image/png;base64,{qr_base64}',
            'secret': totp_secret
        }), 200)
        return response
    except Exception as e:
        logging.error(f"Error enabling 2FA for {email}: {str(e)}")
        return jsonify({'message': 'Failed to enable 2FA'}), 500
    finally:
        conn.close()
@auth_bp.route('/verify-2fa', methods=['POST'])
@jwt_required()
def verify_2fa():
    """
    Xác thực mã 2FA từ người dùng
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            totp_code:
              type: string
              description: 6-digit TOTP code from authenticator app
              example: "123456"
    responses:
      200:
        description: 2FA verified successfully
        content:
          application/json:
            example:
              message: 2FA verified successfully
              is_2fa_enabled: true
      400:
        description: Invalid or missing TOTP code
      404:
        description: User not found or 2FA not enabled
      500:
        description: Server error
    """
    email = get_jwt_identity()
    data = request.get_json()
    if not data or 'totp_code' not in data:
        return jsonify({'message': 'Invalid or missing TOTP code'}), 400
    
    totp_code = data['totp_code'].strip()
    if len(totp_code) != 6 or not totp_code.isdigit():
        return jsonify({'message': 'Invalid TOTP code'}), 400

    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT verified, totp_secret, is_2fa_enabled FROM users WHERE email = %s', (email,))
        user = c.fetchone()
        if not user:
            return jsonify({'message': 'User not found'}), 404
        if not user['verified']:
            return jsonify({'message': 'User not verified'}), 400
        if not user['totp_secret'] or not user['is_2fa_enabled']:
            return jsonify({'message': '2FA not enabled for this user'}), 404

        totp = pyotp.TOTP(user['totp_secret'])
        if not totp.verify(totp_code):
            return jsonify({'message': 'Invalid TOTP code'}), 400

        conn.commit()
        conn.close()
        return jsonify({'message': '2FA verified successfully', 'is_2fa_enabled': True}), 200
    except Exception as e:
        logging.error(f"Error verifying 2FA for {email}: {str(e)}")
        return jsonify({'message': 'Failed to verify 2FA'}), 500
    finally:
        conn.close()
@auth_bp.route('/2fa-status', methods=['GET'])
@jwt_required()
def check_2fa_status():
    """
    Kiểm tra trạng thái 2FA của người dùng
    ---
    tags:
      - Authentication
    responses:
      200:
        description: Returns 2FA status
        content:
          application/json:
            example:
              is_2fa_enabled: true
      404:
        description: User not found
      500:
        description: Server error
    """
    email = get_jwt_identity()

    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT is_2fa_enabled FROM users WHERE email = %s', (email,))
        user = c.fetchone()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        return jsonify({'is_2fa_enabled': user['is_2fa_enabled'] or False}), 200
    except Exception as e:
        logging.error(f"Error checking 2FA status for {email}: {str(e)}")
        return jsonify({'message': 'Failed to check 2FA status'}), 500
    finally:
        conn.close()
    
def send_device_verification_email(email, fingerprint):
    """Gửi email xác minh thiết bị lạ."""
    token = ts.dumps({"email": email, "fingerprint": fingerprint}, salt='device-verify')
    verify_link = f"http://localhost:8000/api/auth/verify-device?token={token}"
    msg = MIMEText(f"New device detected. Verify it here: {verify_link}\nLink expires in 10 minutes.")
    msg['Subject'] = "Verify New Device"
    msg['From'] = os.getenv('EMAIL_FROM')
    msg['To'] = email

    try:
        with smtplib.SMTP(os.getenv('SMTP_SERVER'), int(os.getenv('SMTP_PORT'))) as server:
            server.starttls()
            server.login(os.getenv('SMTP_USERNAME'), os.getenv('SMTP_PASSWORD'))
            server.sendmail(os.getenv('EMAIL_FROM'), email, msg.as_string())
        logging.info(f"Device verification email sent to {email}")
    except Exception as e:
        logging.error(f"Failed to send device verification email to {email}: {str(e)}")
        raise

def verify_device(email, fingerprint):
    """Kiểm tra và lưu fingerprint thiết bị."""
    redis_key = f"device:{email}"
    known_devices = redis_client.get(redis_key)
    if known_devices:
        known_devices = json.loads(known_devices)
        if fingerprint not in known_devices:
            return False
    else:
        known_devices = [fingerprint]
        redis_client.setex(redis_key, 30*24*3600, json.dumps(known_devices))
    return True
def get_device_fingerprint(request):
    user_agent = request.headers.get('User-Agent', '')
    accept_language = request.headers.get('Accept-Language', '')
    # Có thể thu thập thêm: screen resolution, timezone từ frontend
    fingerprint = hashlib.sha256(f"{user_agent}:{accept_language}".encode()).hexdigest()
    return fingerprint
@auth_bp.route('/disable-2fa', methods=['POST'])
@jwt_required()
def disable_2fa():
    """
    Tắt 2FA cho người dùng
    ---
    tags:
      - Authentication
    responses:
      200:
        description: 2FA disabled successfully
        content:
          application/json:
            example:
              message: 2FA disabled successfully
      400:
        description: 2FA not enabled
      404:
        description: User not found
      500:
        description: Server error
    """
    email = get_jwt_identity()

    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT is_2fa_enabled FROM users WHERE email = %s', (email,))
        user = c.fetchone()
        if not user:
            return jsonify({'message': 'User not found'}), 404
        if not user['is_2fa_enabled']:
            return jsonify({'message': '2FA not enabled'}), 400

        c.execute('UPDATE users SET is_2fa_enabled = FALSE, totp_secret = NULL WHERE email = %s', (email,))
        conn.commit()
        conn.close()
        return jsonify({'message': '2FA disabled successfully'}), 200
    except Exception as e:
        logging.error(f"Error disabling 2FA for {email}: {str(e)}")
        return jsonify({'message': 'Failed to disable 2FA'}), 500
    finally:
        conn.close()

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
    email = sanitize_input(data.get('email'))
    password = data.get('password')
    totp_code = data.get('totp_code')
    recaptcha_response = data.get('recaptcha_response')
    print(recaptcha_response)
    ip = request.remote_addr
    login_key = f"login:{email}:{ip}"
    max_attempts = 5
    # if not check_rate_limit(ip, login_key, max_attempts=max_attempts, expire=900):
    #     return jsonify({'message': 'Too many login attempts. Please try again later.'}), 429

    attempts = redis_client.get(login_key)
    if attempts and int(attempts) >= 3 and not verify_recaptcha(recaptcha_response):
        return jsonify({'message': 'Invalid CAPTCHA'}), 400

    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = c.fetchone()

        if not user or not user['verified'] or not check_password(user['password'], password):
            redis_client.incr(login_key)
            logging.warning(f"Failed login attempt for {email}")
            return jsonify({'message': 'Invalid credentials or unverified email'}), 401

        if user.get('is_2fa_enabled') and not totp_code:
            redis_client.incr(login_key)
            logging.warning(f"2FA required for {email}")
            return jsonify({'message': '2FA code required', 'requires_2fa': True}), 401
        if user.get('is_2fa_enabled') and user.get('totp_secret'):
            totp = pyotp.TOTP(user['totp_secret'])
            if not totp.verify(totp_code):
                redis_client.incr(login_key)
                logging.warning(f"Invalid 2FA code for {email}")
                return jsonify({'message': 'Invalid 2FA code'}), 401

        print("\n--- BẮT ĐẦU DEBUG GIÁ TRỊ IDENTITY ---")
        user_identity_value = user.get('id')
        print(f"Giá trị của user['id']: {user_identity_value}")
        print(f"Kiểu dữ liệu của user['id']: {type(user_identity_value)}")
        print("--------------------------------------\n")
        redis_client.delete(login_key)
        identity={'email':email,'user_id':user['id']}
        user_identity = str(user['id'])
        access_token = create_access_token(identity=user_identity, additional_claims={'role': user['role'],'email':user['email']})
        refresh_token = create_refresh_token(identity=user_identity)
        refresh_jti=get_jti(encoded_token=refresh_token)
        fingerprint=get_device_fingerprint(request)
        user_agent=request.headers.get('User-Agent','')
        ip=request.remote_addr

        c.execute("""
        SELECT id from user_devices where user_id=%s and device_fingerprint = %s
        """,(user['id'],fingerprint))

        existing_device=c.fetchone()
        if existing_device:
            c.execute("""
            UPDATE user_devices SET last_active_at=CURRENT_TIMESTAMP,jti=%s WHERE user_id=%s 
                      """,(refresh_jti,existing_device['id']))
        else:
            c.execute("""
                INSERT INTO user_devices (user_id, device_fingerprint, user_agent, ip_address,jti) VALUES(%s,%s,%s,%s,%s)
            """,
            (user['id'], fingerprint, user_agent, ip,refresh_jti))
        conn.commit()
        csrf_token = generate_csrf_token()
        return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'csrf_token': csrf_token,
        'role': user['role'],
        'email': email
        }), 200
    except Exception as e:
        logging.error(f"Error logging in user {email}: {str(e)}")
        return jsonify({'message': 'Login failed'}), 500
    finally:
        conn.close()

ts = URLSafeTimedSerializer(os.getenv("SECRET_KEY"))
@auth_bp.route("/devices",methods=['GET'])
@jwt_required()
def get_devices():
    """
    Lấy danh sách các thiết bị đang đăng nhập của người dùng.
    ---
    tags:
      - Device Management
    security:
      - Bearer: []
    responses:
      200:
        description: Danh sách các thiết bị.
    """
    user_id=get_jwt_identity()
    try:
        conn=get_db_connection()
        c=conn.cursor(cursor_factory=RealDictCursor)
        c.execute(
            "SELECT id,user_agent,ip_address,last_active_at,created_at from user_devices where user_id=%s",(user_id,)
        )
        devices=c.fetchall()
        return jsonify(devices),200
    except Exception as e:
        logging.error(f"Error fetching devices for user {user_id}: {e}")
        return jsonify({'message': 'Could not retrieve devices'}), 500
    finally:
        if conn:
            conn.close()
    
@auth_bp.route('/request-magic-link', methods=['POST'])
def request_magic_link():
    """
    Request a magic login link
    ---
    tags:
      - Auth
    parameters:
      - name: email
        in: body
        type: string
        required: true
        description: Email to send the magic link to
    responses:
      200:
        description: Magic link sent
      404:
        description: Email not found
      429:
        description: Too many requests
      500:
        description: Server error
    """
    data = request.get_json()
    email = sanitize_input(data.get('email'))
    ip = request.remote_addr

    if not check_rate_limit(ip, f"magic:{email}", max_attempts=3, expire=600):
        return jsonify({'message': 'Too many requests. Try again later.'}), 429

    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT * FROM users WHERE email = %s AND verified = 1', (email,))
        user = c.fetchone()
        if not user:
            return jsonify({'message': 'Email not found or unverified'}), 404

        ts = URLSafeTimedSerializer(os.getenv("SECRET_KEY"))
        token = ts.dumps(email, salt='magic-link')
        magic_link = f"http://127.0.0.1:8000/api/auth/magic-login?token={token}"

        msg = MIMEText(f"Click to login: {magic_link}\nLink expires in 10 minutes.")
        msg['Subject'] = "Your Netflix Magic Login Link"
        msg['From'] = os.getenv('EMAIL_FROM')
        msg['To'] = email

        with smtplib.SMTP(os.getenv('SMTP_SERVER'), int(os.getenv('SMTP_PORT'))) as server:
            server.starttls()
            server.login(os.getenv('SMTP_USERNAME'), os.getenv('SMTP_PASSWORD'))
            server.sendmail(os.getenv('EMAIL_FROM'), email, msg.as_string())

        logging.info(f"Magic link sent to {email}")
        return jsonify({'message': 'Magic link sent to your email'}), 200
    except Exception as e:
        logging.error(f"Error sending magic link to {email}: {str(e)}")
        return jsonify({'message': 'Failed to send magic link'}), 500
    finally:
        conn.close()

@auth_bp.route('/magic-login', methods=['GET'])
def magic_login():
    """
    Magic login handler
    ---
    parameters:
      - name: token
        in: query
        type: string
        required: true
    responses:
      302:
        description: Redirects to main.html
      400:
        description: Invalid or expired token
    """
    token = request.args.get('token')
    try:
        email = ts.loads(token, salt='magic-link', max_age=600)  # Hết hạn sau 10 phút
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT * FROM users WHERE email = %s AND verified = 1', (email,))
        user = c.fetchone()
        if not user:
            return jsonify({'message': 'Invalid or expired token'}), 400

        access_token = create_access_token(identity=email, additional_claims={'role': user['role']})
        refresh_token = create_refresh_token(identity=email)
        csrf_token = generate_csrf_token()

        # Redirect kèm token trên URL để frontend lấy và lưu vào localStorage
        redirect_url = f'http://127.0.0.1:5501/frontend/main.html?access_token={access_token}&refresh_token={refresh_token}'
        response = make_response(redirect(redirect_url))
        # Không cần set_cookie nữa
        logging.info(f"User {email} logged in via magic link")
        return response
    except Exception as e:
        logging.error(f"Error processing magic link: {str(e)}")
        return jsonify({'message': 'Invalid or expired token'}), 400
    finally:
        conn.close()
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
    csrf_token = generate_csrf_token()

    logging.info(f"Token refreshed for {current_user}")
    response = make_response(jsonify({'access_token': new_access_token}), 200)
    response = set_csrf_cookie(response, csrf_token)
    return response

@auth_bp.route('/check_session', methods=['GET'])
@jwt_required()
def check_session():
    """
    Check if user is logged in
    ---
    tags:
        - Authentication
    security:
        - Bearer: []
    responses:
        200:
            description: User is logged in
    """
    current_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    user_id = get_jwt_identity()

    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute('SELECT last_ip, totp_secret, role FROM users WHERE id = %s', (user_id,))
    result = c.fetchone()
    conn.close()

    if not result:
        return jsonify({'message': 'User not found'}), 404

    last_ip = result['last_ip']
    if last_ip and last_ip != current_ip:
        logging.warning(f"Suspicious session for {user_id}: IP changed from {last_ip} to {current_ip}")

    response = make_response(jsonify({
        'ip': current_ip,
        'user_agent': user_agent,
        'totp_secret': bool(result['totp_secret']),
        'role': result['role'] or 'user'
    }), 200)
    return response

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Log out user
    ---
    tags:
        - Authentication
    security:
        - Bearer: []
    responses:
        200:
            description: User logged out
    """
    jti = get_jwt()['jti']
    try:
        redis_client.setex(jti, 24 * 3600, 'blacklisted')
        logging.info(f"User {get_jwt_identity()} logged out, token {jti} blacklisted")
        response = make_response(jsonify({'message': 'Successfully logged out'}), 200)
        response.delete_cookie('csrf_token')
        return response
    except redis.RedisError as e:
        logging.error(f"Error blacklisting token: {str(e)}")
        response = make_response(jsonify({'message': 'Logout successful (token not blacklisted)'}), 200)
        response.delete_cookie('csrf_token')
        return response

@auth_bp.route('/api/content', methods=['GET'])
@jwt_required()
def get_content():
    """
    Get content for user
    ---
    tags:
        - Content
    security:
        - Bearer: []
    responses:
        200:
            description: Content for user
    """
    email = get_jwt_identity()
    claims = get_jwt()
    role = claims.get('role', 'user')

    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)

    try:
        if role == 'user':
            c.execute('SELECT id, title, video_url, thumbnail_url FROM videos WHERE category = %s LIMIT 6', ('popular',))
            content = c.fetchall()
        elif role == 'admin':
            c.execute('SELECT email, username, role, verified FROM users LIMIT 10')
            content = c.fetchall()
        elif role == 'production':
            c.execute('SELECT id, title, video_url, thumbnail_url, category FROM videos LIMIT 10')
            content = c.fetchall()
        else:
            return jsonify({'message': 'Invalid role'}), 403

        response = make_response(jsonify({'role': role, 'content': content}), 200)
        return response
    except Exception as e:
        logging.error(f"Error fetching content for {email}: {str(e)}")
        return jsonify({'message': 'Error fetching content'}), 500
    finally:
        c.close()
        conn.close()

@auth_bp.route('/users/<email>', methods=['PATCH'])
@jwt_required()
def update_user(email):
    """
    Update user
    ---
    tags:
        - User
        - Update
    security:
        - Bearer: []
    parameters:
        - name: email
          in: path
          type: string
          required: true
          description: The email of the user to update
        - name: body
          in: body
          required: true
          schema:
            type: object
            properties:
              role:
                type: string
                example: admin
    responses:
        200:
            description: User role updated
        400:
            description: Invalid request
        403:
            description: Unauthorized
        500:
            description: Internal server error
    """
    email = sanitize_input(email)
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    data = request.get_json()
    new_role = sanitize_input(data.get('role'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('UPDATE users SET role = %s WHERE email = %s', (new_role, email))
    conn.commit()
    conn.close()
    return jsonify({'message': 'User role updated'}), 200
@auth_bp.route('/devices/<int:device_id>/logout', methods=['POST'])
@jwt_required()
def logout_device(device_id):
    """
    Đăng xuất khỏi một thiết bị cụ thể.
    ---
    tags:
      - Device Management
    description: |
      Cho phép người dùng đăng xuất khỏi một thiết bị cụ thể bằng cách xác định `device_id`.
      Thao tác này sẽ:
        - Xác thực người dùng qua JWT.
        - Kiểm tra xem thiết bị có thuộc về người dùng không.
        - Đưa `jti` của thiết bị vào danh sách blacklist (Redis).
        - Xóa thiết bị khỏi bảng `user_devices`.
    parameters:
      - name: device_id
        in: path
        type: integer
        required: true
        description: ID của thiết bị cần đăng xuất.
    security:
      - Bearer: []
    responses:
      200:
        description: Đăng xuất thiết bị thành công.
        schema:
          type: object
          properties:
            message:
              type: string
              example: Device logged out successfully
      404:
        description: Thiết bị không tồn tại hoặc không thuộc về người dùng.
        schema:
          type: object
          properties:
            message:
              type: string
              example: Device not found or you do not have permission
      500:
        description: Lỗi máy chủ khi xử lý đăng xuất.
        schema:
          type: object
          properties:
            message:
              type: string
              example: Failed to log out device
    """
    user_id = get_jwt_identity()
    
    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        # 1. Lấy jti của thiết bị cần đăng xuất, đảm bảo nó thuộc về người dùng hiện tại
        c.execute(
            "SELECT jti FROM user_devices WHERE id = %s AND user_id = %s",
            (device_id, user_id)    
        )
        device = c.fetchone()
        
        if not device:
            return jsonify({'message': 'Device not found or you do not have permission'}), 404
            
        # 2. Blacklist JTI của refresh token trong Redis
        jti_to_blacklist = device['jti']
        # Lấy thời gian hết hạn của refresh token để set cho blacklist
        # Mặc định là 30 ngày cho refresh token
        expires = timedelta(days=30) 
        redis_client.setex(jti_to_blacklist, expires, 'blacklisted')
        
        # 3. Xóa thiết bị khỏi bảng user_devices
        c.execute("DELETE FROM user_devices WHERE id = %s", (device_id,))
        conn.commit()
        
        logging.info(f"User {user_id} logged out device {device_id} (jti: {jti_to_blacklist})")
        return jsonify({'message': 'Device logged out successfully'}), 200
        
    except Exception as e:
        logging.error(f"Error logging out device {device_id} for user {user_id}: {e}")
        return jsonify({'message': 'Failed to log out device'}), 500
    finally:
        if conn:
            conn.close()
@auth_bp.route('/devices/logout-all', methods=['POST'])
@jwt_required()
def logout_all_devices():
    """
    Đăng xuất khỏi tất cả các thiết bị.
    ---
    tags:
      - Device Management
    description: |
      Đăng xuất khỏi **tất cả các thiết bị** đã đăng nhập trước đó của người dùng hiện tại.
      Thao tác này sẽ:
        - Lấy tất cả `jti` (JWT ID) của người dùng từ cơ sở dữ liệu.
        - Đưa tất cả `jti` vào danh sách blacklist (Redis), khiến token bị vô hiệu hóa.
        - Xóa tất cả bản ghi thiết bị của người dùng khỏi bảng `user_devices`.
        - Token hiện tại cũng sẽ bị vô hiệu hóa, vì vậy client cần đăng nhập lại.
    security:
      - Bearer: []
    responses:
      200:
        description: Đăng xuất tất cả thiết bị thành công.
        schema:
          type: object
          properties:
            message:
              type: string
              example: Successfully logged out from all devices. You will be logged out shortly.
      500:
        description: Lỗi máy chủ khi xử lý đăng xuất hàng loạt.
        schema:
          type: object
          properties:
            message:
              type: string
              example: Failed to log out all devices
    """
    user_id = get_jwt_identity()
    
    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)

        # 1. Lấy tất cả jti của người dùng
        c.execute("SELECT jti FROM user_devices WHERE user_id = %s", (user_id,))
        devices = c.fetchall()

        # 2. Blacklist tất cả các jti
        expires = timedelta(days=30)
        pipeline = redis_client.pipeline()
        for device in devices:
            pipeline.setex(device['jti'], expires, 'blacklisted')
        pipeline.execute()

        # 3. Xóa tất cả thiết bị của người dùng khỏi DB
        c.execute("DELETE FROM user_devices WHERE user_id = %s", (user_id,))
        conn.commit()
        
        logging.info(f"User {user_id} logged out from all devices.")
        # Lưu ý: Hành động này cũng sẽ vô hiệu hóa token của phiên hiện tại.
        # Frontend cần xử lý bằng cách điều hướng người dùng về trang đăng nhập.
        return jsonify({'message': 'Successfully logged out from all devices. You will be logged out shortly.'}), 200

    except Exception as e:
        logging.error(f"Error logging out all devices for user {user_id}: {e}")
        return jsonify({'message': 'Failed to log out all devices'}), 500
    finally:
        if conn:
            conn.close()
@auth_bp.after_request
def update_last_active(response):
    try:
        try:
            verify_jwt_in_request()
        except NoAuthorizationError:
            return response  # Không có JWT, bỏ qua

        user_id = get_jwt_identity()
        if not user_id:
            return response

        # Cập nhật last_active như cũ
        fingerprint = get_device_fingerprint(request)

        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            "UPDATE user_devices SET last_active_at = CURRENT_TIMESTAMP WHERE user_id = %s AND device_fingerprint = %s",
            (user_id, fingerprint)
        )
        conn.commit()
    except Exception as e:
        logging.warning(f"Could not update last_active: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()

    return response

@auth_bp.route('/test-captcha', methods=['POST'])
def test_captcha():
    """
    Kiểm tra xác thực reCAPTCHA từ phía client.

    Nhận một JSON object từ request chứa trường 'recaptcha_response',
    sau đó gọi hàm verify_recaptcha để kiểm tra tính hợp lệ của token.

    Returns:
        Response: JSON chứa kết quả xác thực với khóa 'verified' là True hoặc False.
                  Nếu thiếu trường 'recaptcha_response', trả về mã lỗi 400.
    """
    data = request.get_json()
    if not data or 'recaptcha_response' not in data:
        return jsonify({"message": "Missing recaptcha_response"}), 400

    token = data['recaptcha_response']
    
    logging.info(f"--- BẮT ĐẦU TEST CAPTCHA ---")
    logging.info(f"Nhận được token trong /test-captcha: ...{token[-6:]}")
    
    is_verified = verify_recaptcha(token)
    
    logging.info(f"--- KẾT THÚC TEST CAPTCHA ---")

    return jsonify({"verified": is_verified})
