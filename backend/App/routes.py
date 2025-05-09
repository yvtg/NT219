from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from .security import role_required
from .database import get_db_connection
from psycopg2.extras import RealDictCursor
import logging
import requests
import os

routes_bp = Blueprint('routes', __name__)

# API công khai
@routes_bp.route('/public', methods=['GET'])
def public_content():
    """
    Get public content
    ---
    tags:
      - Public
    responses:
      200:
        description: Public content retrieved
    """
    return jsonify({'message': 'This is public content'}), 200

# API quản trị
@routes_bp.route('/admin/users', methods=['GET'])
@jwt_required()
@role_required('admin')
def manage_users():
    """
    Get all users (Admin only)
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    responses:
      200:
        description: List of users
      403:
        description: Insufficient permissions
    """
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute('SELECT id, username, email, role FROM users')
    users = c.fetchall()
    conn.close()
    logging.info(f"Admin accessed user list")
    return jsonify(users), 200

# Đổi mật khẩu
@routes_bp.route('/change_password', methods=['POST'])
@jwt_required()
def change_password():
    """
    Change user password
    ---
    tags:
      - User
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - new_password
            - recaptcha_response
          properties:
            new_password:
              type: string
              example: NewPassword123!
            recaptcha_response:
              type: string
              example: recaptcha-token
    responses:
      200:
        description: Password changed successfully
      400:
        description: reCAPTCHA verification failed
      500:
        description: Error changing password
    """
    data = request.get_json()
    new_password = data.get('new_password')
    recaptcha_response = data.get('recaptcha_response')
    email = get_jwt_identity()

    # Kiểm tra reCAPTCHA v3
    recaptcha_secret = os.getenv('RECAPTCHA_SECRET_KEY')
    recaptcha_verify = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={'secret': recaptcha_secret, 'response': recaptcha_response}
    ).json()
    if not recaptcha_verify['success'] or recaptcha_verify['score'] < 0.5:
        return jsonify({'message': 'reCAPTCHA verification failed'}), 400

    # Cập nhật mật khẩu
    try:
        conn = get_db_connection()
        c = conn.cursor()
        from .security import hash_password
        hashed_password = hash_password(new_password)
        c.execute('UPDATE users SET password = %s WHERE email = %s', (hashed_password, email))
        conn.commit()
        logging.info(f"Password changed for {email}")
        return jsonify({'message': 'Password changed successfully'}), 200
    except Exception as e:
        logging.error(f"Error changing password for {email}: {str(e)}")
        return jsonify({'message': 'Error changing password'}), 500
    finally:
        conn.close()

# Kiểm tra phiên
@routes_bp.route('/check_session', methods=['GET'])
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
    """
    current_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    email = get_jwt_identity()

    # Kiểm tra IP bất thường
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute('SELECT last_ip FROM users WHERE email = %s', (email,))
    result = c.fetchone()
    last_ip = result['last_ip'] if result else None
    conn.close()

    if last_ip and last_ip != current_ip:
        logging.warning(f"Suspicious session for {email}: IP changed from {last_ip} to {current_ip}")
        # Gửi OTP để xác minh (tái sử dụng Twilio nếu cần)

    return jsonify({'ip': current_ip, 'user_agent': user_agent}), 200