from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from functools import wraps
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from flask import jsonify

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