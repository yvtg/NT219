from datetime import datetime
import re
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from functools import wraps
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from flask import jsonify
import os

from jose import JWTError
import jwt 

ph = PasswordHasher()

# Mã hóa mật khẩu bằng Argon2
def hash_password(password):
    return ph.hash(password)

# Kiểm tra mật khẩu
def check_password(hashed_password, password):
    try:
        ph.verify(hashed_password, password)
        return True
    except VerifyMismatchError:
        return False

# Kiểm tra vai trò
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims['role'] != role:
                return jsonify({'message': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator
def sanitize_input(value: str) -> str:
    """Sanitize input to prevent XSS by removing dangerous characters."""
    if not value:
        return value
    # Loại bỏ các ký tự nguy hiểm
    dangerous_chars = re.compile(r'[<>{}\[\]\\/;`]')
    return dangerous_chars.sub('', value)

def generate_csrf_token() -> str:
    """Tạo CSRF token an toàn."""
    return secrets.token_urlsafe(32)

def set_csrf_cookie(response, csrf_token: str):
    """Đặt CSRF token vào cookie."""
    response.set_cookie(
        key='csrf_token',
        value=csrf_token,
        httponly=True,
        secure=False,  # Chỉ hoạt động với HTTPS
        samesite='Strict',
        max_age=3600
    )
    return response
SECRET_KEYS = [
    {"key": os.getenv("JWT_SECRET"), "expires": datetime(2025, 12, 31)},
    {"key": os.getenv("JWT_SECRET_2"), "expires": datetime(2026, 6, 30)},
]

def decode_jwt(token: str):
    for secret in SECRET_KEYS:
        if secret["expires"] < datetime.now():
            continue
        try:
            payload = jwt.decode(token, secret["key"], algorithms=["HS256"])
            return payload
        except JWTError:
            continue
    raise JWTError("Invalid token")