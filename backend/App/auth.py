from dotenv import load_dotenv
from flask import Blueprint, redirect, request, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt, jwt_required, get_jwt_identity
import psycopg2
from psycopg2.extras import RealDictCursor
from .security import hash_password, check_password
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
jwt = JWTManager()

load_dotenv(dotenv_path='D:\\NT219\\NT219\\backend\\config\\.env')

redis_client = redis.Redis(host='localhost', port=6379, db=0)
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')
RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

request_counts = defaultdict(int)
request_timestamps = defaultdict(list)

auth_bp = Blueprint('auth', __name__)

# Store IP-based request counts (in-memory for simplicity; use Redis in production)
request_counts = defaultdict(int)
request_timestamps = defaultdict(list)

# Hàm gửi email xác thực
def send_verification_email(email, verification_token):
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT'))
    smtp_username = os.getenv('SMTP_USERNAME')
    smtp_password = os.getenv('SMTP_PASSWORD')
    email_from = os.getenv('EMAIL_FROM')

    verification_link = f"http://localhost:8000/api/verify_email?token={verification_token}&email={email}"

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
    """
    Kiểm tra giới hạn số lần thử (dùng Redis)
    """
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
    """
    Kiểm tra độ mạnh của mật khẩu
    """
    # Độ dài tối thiểu
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    # Kiểm tra các loại ký tự
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    
    # Kiểm tra không chứa username hoặc email
    if username.lower() in password.lower() or email.lower() in password.lower():
        return False, "Password must not contain username or email"
    
    # Kiểm tra các chuỗi phổ biến (có thể mở rộng danh sách)
    common_patterns = ["password", "1234", "qwerty"]
    if any(pattern in password.lower() for pattern in common_patterns):
        return False, "Password contains common patterns"
    
    return True, ""
def verify_recaptcha(recaptcha_response):
    """
    Xác minh Google reCAPTCHA
    """
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': recaptcha_response
    }
    response = requests.post(RECAPTCHA_VERIFY_URL, data=payload)
    result = response.json()
    return result.get('success', False)

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
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not all([username, email, password]):
        return jsonify({'message': 'Missing required fields'}), 400

    is_strong, message = is_strong_password(password, username, email)
    if not is_strong:
        return jsonify({'message': message}), 400

    ip = request.remote_addr
    if not check_rate_limit(ip, 'register'):
        return jsonify({'message': 'Too many registration attempts. Please try again later.'}), 400

    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        return jsonify({'message': 'Invalid email'}), 400

    verification_token = str(uuid.uuid4())

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

@auth_bp.route('/enable-2fa', methods=['POST'])
@jwt_required()
def enable_2fa():
    """
    Kích hoạt 2FA cho người dùng
    """
    email = get_jwt_identity()

    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT verified FROM users WHERE email = %s', (email,))
        user = c.fetchone()
        if not user or not user['verified']:
            return jsonify({'message': 'User not found or not verified'}), 400

        # Tạo secret key cho TOTP
        totp_secret = pyotp.random_base32()
        c.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT')
        c.execute('UPDATE users SET totp_secret = %s WHERE email = %s', (totp_secret, email))
        conn.commit()

        # Tạo URI cho ứng dụng 2FA
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=email, issuer_name='Netflix')
        
        # Tạo QR code
        qr = qrcode.QRCode()
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        logging.info(f"2FA enabled for {email}")
        return jsonify({
            'message': '2FA enabled, scan the QR code with your authenticator app',
            'qr_code': f'data:image/png;base64,{qr_base64}',
            'secret': totp_secret
        }), 200
    except Exception as e:
        logging.error(f"Error enabling 2FA for {email}: {str(e)}")
        return jsonify({'message': 'Failed to enable 2FA'}), 500
    finally:
        conn.close()

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
    totp_code = data.get('totp_code')
    recaptcha_response = data.get('recaptcha_response')

    # Kiểm tra giới hạn số lần đăng nhập
    ip = request.remote_addr
    login_key = f"login:{email}:{ip}"
    max_attempts = 5
    if not check_rate_limit(ip, login_key, max_attempts=max_attempts, expire=900):
        return jsonify({'message': 'Too many login attempts. Please try again later.'}), 429

    # Kiểm tra CAPTCHA sau 3 lần thử thất bại
    attempts = redis_client.get(login_key)
    if attempts and int(attempts) >= 3 and not verify_recaptcha(recaptcha_response):
        return jsonify({'message': 'Invalid CAPTCHA'}), 400

    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = c.fetchone()

        if not user:
            redis_client.incr(login_key)
            logging.warning(f"Failed login attempt for {email}: User not found")
            return jsonify({'message': 'Invalid credentials'}), 401
        if not user['verified']:
            redis_client.incr(login_key)
            logging.warning(f"Failed login attempt for {email}: Email not verified")
            return jsonify({'message': 'Please verify your email before logging in'}), 401
        if not check_password(user['password'], password):
            redis_client.incr(login_key)
            logging.warning(f"Failed login attempt for {email} from IP {ip}")
            return jsonify({'message': 'Invalid credentials'}), 401

        # Kiểm tra mã TOTP nếu 2FA được kích hoạt
        if user.get('totp_secret'):
            totp = pyotp.TOTP(user['totp_secret'])
            if not totp.verify(totp_code):
                redis_client.incr(login_key)
                logging.warning(f"Invalid 2FA code for {email}")
                return jsonify({'message': 'Invalid 2FA code'}), 401

        # Đăng nhập thành công, reset số lần thử
        redis_client.delete(login_key)
        access_token = create_access_token(identity=email, additional_claims={'role': user['role']})
        refresh_token = create_refresh_token(identity=email)
        logging.info(f"User {email} logged in from IP {ip}")
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
    except Exception as e:
        logging.error(f"Error logging in user {email}: {str(e)}")
        return jsonify({'message': 'Login failed'}), 500
    finally:
        conn.close()
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
        description: Session details including role and 2FA status
      401:
        description: Unauthorized
    """
    current_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    email = get_jwt_identity()

    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute('SELECT last_ip, totp_secret, role FROM users WHERE email = %s', (email,))
    result = c.fetchone()
    conn.close()

    if not result:
        return jsonify({'message': 'User not found'}), 404

    last_ip = result['last_ip']
    if last_ip and last_ip != current_ip:
        logging.warning(f"Suspicious session for {email}: IP changed from {last_ip} to {current_ip}")

    return jsonify({
        'ip': current_ip,
        'user_agent': user_agent,
        'email': email,
        'totp_secret': bool(result['totp_secret']),  # True nếu đã kích hoạt 2FA
        'role': result['role'] or 'user'  # Đảm bảo có role, mặc định là user
    }), 200
@auth_bp.route('/logout', methods=['POST'])  # Dùng POST thay vì GET cho hành động thay đổi trạng thái
@jwt_required()
def logout():
    """
    Log out user by blacklisting JWT
    ---
    tags:
      - User
    security:
      - Bearer: []
    responses:
      200:
        description: Successfully logged out
      401:
        description: Unauthorized
    """
    jti = get_jwt()['jti']  # Lấy ID duy nhất của JWT
    try:
        redis_client.setex(jti, 24 * 3600, 'blacklisted')  # Lưu vào blacklist, hết hạn sau 24h
        logging.info(f"User {get_jwt_identity()} logged out, token {jti} blacklisted")
        return jsonify({'message': 'Successfully logged out'}), 200
    except redis.RedisError as e:
        logging.error(f"Error blacklisting token: {str(e)}")
        return jsonify({'message': 'Logout successful (token not blacklisted)'}), 200
    
@auth_bp.route('/api/content', methods=['GET'])
@jwt_required()
def get_content():
    email = get_jwt_identity()
    claims = get_jwt()
    role = claims.get('role', 'user')

    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)

    try:
        if role == 'user':
            # Trả về danh sách video cho user
            c.execute('SELECT id, title, video_url, thumbnail_url FROM videos WHERE category = %s LIMIT 6', ('popular',))
            content = c.fetchall()
        elif role == 'admin':
            # Trả về danh sách người dùng cho admin
            c.execute('SELECT email, username, role, verified FROM users LIMIT 10')
            content = c.fetchall()
        elif role == 'production':
            # Trả về danh sách video để quản lý cho production
            c.execute('SELECT id, title, video_url, thumbnail_url, category FROM videos LIMIT 10')
            content = c.fetchall()
        else:
            return jsonify({'message': 'Invalid role'}), 403

        return jsonify({'role': role, 'content': content}), 200
    except Exception as e:
        logging.error(f"Error fetching content for {email}: {str(e)}")
        return jsonify({'message': 'Error fetching content'}), 500
    finally:
        c.close()
        conn.close()
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = redis_client.get(jti)
    return token is not None
@auth_bp.route('/users/<email>', methods=['PATCH'])
@jwt_required()
def update_user(email):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    data = request.get_json()
    new_role = data.get('role')

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('UPDATE users SET role = %s WHERE email = %s', (new_role, email))
    conn.commit()
    conn.close()
    return jsonify({'message': 'User role updated'}), 200