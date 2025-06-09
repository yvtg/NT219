from flask import Blueprint, Response, send_file, request, jsonify, abort, make_response, stream_with_context
from flask_jwt_extended import jwt_required
from werkzeug.utils import secure_filename
from .chaotic_cipher import ChaoticCipher
from .config import CHAOTIC_PARAMS, CHUNK_SIZE, VIDEOS_DIR, WARMUP_ITERATIONS
import os
import logging
import mimetypes
import hashlib
import re
import functools
from collections import OrderedDict
from Crypto.Cipher import AES
from psycopg2.extras import RealDictCursor
from .database import get_db_connection
from .storage import get_public_url
import requests
from flask import current_app
import time

stream_bp = Blueprint('stream', __name__)


# ===============================
#  API LẤY VÀ PHÁT VIDEO THEO ID
# ===============================

# stream video


# @stream_bp.route('/video/<int:video_id>', methods=['GET', 'OPTIONS'])
# def get_video_by_id(video_id):
#     logging.info(f"Received request for video_id: {video_id}")
#     logging.info(f"Request headers: {dict(request.headers)}")

#     try:
#         conn = get_db_connection()
#         c = conn.cursor(cursor_factory=RealDictCursor)

#         c.execute(
#             'SELECT id, title, video_url FROM videos WHERE id = %s', (video_id,))
#         video = c.fetchone()

#         if not video:
#             return make_cors_response({'error': 'Video not found'}, 404)

#         # Xử lý Range request
#         range_header = request.headers.get('Range')
#         headers = {}

#         if range_header:
#             headers['Range'] = range_header
#             logging.info(
#                 f"Forwarding Range header to Supabase: {range_header}")

#         # Gọi Supabase để lấy video
#         supabase_response = requests.get(
#             video['video_url'],
#             headers=headers,
#             stream=True
#         )

#         logging.info(
#             f"Supabase response status: {supabase_response.status_code}")
#         logging.info(
#             f"Supabase response headers: {dict(supabase_response.headers)}")

#         if supabase_response.status_code not in [200, 206]:
#             logging.error(f"Supabase error response: {supabase_response.text}")
#             return make_cors_response(
#                 {'error': 'Video file not found or inaccessible'},
#                 supabase_response.status_code
#             )

#         # Lấy Content-Length và Content-Range từ Supabase
#         content_length = supabase_response.headers.get('Content-Length')
#         content_range = supabase_response.headers.get('Content-Range')

#         def generate():
#             # Đọc và trả về dữ liệu theo chunk
#             chunk_size = 1024 * 1024  # 1MB chunks
#             for chunk in supabase_response.iter_content(chunk_size=chunk_size):
#                 if chunk:
#                     yield chunk

#         # Tạo response với status code phù hợp
#         response = Response(
#             stream_with_context(generate()),
#             status=supabase_response.status_code,
#             mimetype='video/mp4'
#         )

#         # Copy các header quan trọng từ Supabase
#         if content_length:
#             response.headers['Content-Length'] = content_length
#         if content_range:
#             response.headers['Content-Range'] = content_range
#         response.headers['Accept-Ranges'] = 'bytes'

#         # Thêm CORS headers
#         add_cors_headers(response)

#         # Log response headers để debug
#         logging.info(f"Final response headers: {dict(response.headers)}")

#         return response

#     except Exception as e:
#         logging.error(
#             f"Error streaming video {video_id}: {str(e)}", exc_info=True)
#         return make_cors_response({'error': str(e)}, 500)
#     finally:
#         if 'conn' in locals():
#             conn.close()

# Lấy metadata


@stream_bp.route('/videos/<int:video_id>', methods=['GET'])
def get_video_metadata(video_id):
    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)

        c.execute(
            'SELECT id, title, description FROM videos WHERE id = %s', (video_id,))
        video = c.fetchone()

        if not video:
            return make_cors_response({'error': 'Video not found'}, 404)

        response = make_cors_response({
            'id': video['id'],
            'title': video['title'],
            'description': video['description']
        }, 200)

        return response

    except Exception as e:
        logging.error(f"Error fetching video metadata {video_id}: {str(e)}")
        return make_cors_response({'error': str(e)}, 500)
    finally:
        if 'conn' in locals():
            conn.close()


# Hàm thêm CORS headers


def add_cors_headers(response):
    response.headers.update({
        'Access-Control-Allow-Origin': 'http://127.0.0.1:5501',
        'Access-Control-Allow-Headers': 'Authorization, Range, Content-Type, Accept',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Expose-Headers': 'Content-Range, Accept-Ranges, Content-Length, Content-Type',
        'Access-Control-Max-Age': '3600'
    })

# Tạo JSON response kèm CORS headers


def make_cors_response(data, status):
    response = make_response(jsonify(data), status)
    add_cors_headers(response)
    return response


@stream_bp.route('/stream/key', methods=['GET', 'POST'])
def get_encryption_key():
    try:
        if request.method == 'POST':
            data = request.get_json()
            if not data or 'password' not in data:
                return jsonify({'status': 'error', 'message': 'Password is required'}), 400

            cipher = ChaoticCipher.from_password(data['password'])
            params = {
                'alpha': cipher.alpha,
                'beta': cipher.beta,
                'gamma': cipher.gamma,
                'x0': round(cipher._x_int / ChaoticCipher.INT_SCALE, 10),
                'y0': round(cipher._y_int / ChaoticCipher.INT_SCALE, 10),
                'z0': round(cipher._z_int / ChaoticCipher.INT_SCALE, 10),
                'warmup_iterations': cipher.warmup_iterations
            }
        else:
            params = {
                'alpha': CHAOTIC_PARAMS['alpha'],
                'beta': CHAOTIC_PARAMS['beta'],
                'gamma': CHAOTIC_PARAMS['gamma'],
                'x0': CHAOTIC_PARAMS['x0'],
                'y0': CHAOTIC_PARAMS['y0'],
                'z0': CHAOTIC_PARAMS['z0'],
                'warmup_iterations': WARMUP_ITERATIONS
            }

        logging.info(f'Returning params: {params}')
        return jsonify({'status': 'success', 'params': params})

    except Exception as e:
        logging.error(f'Lỗi khi lấy tham số mã hóa: {str(e)}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Thêm route OPTIONS để xử lý preflight request


@stream_bp.route('/video/<int:video_id>', methods=['OPTIONS'])
def handle_options_request(video_id):
    response = make_response()
    add_cors_headers(response)
    return response

# Thêm CORS headers


def add_cors_headers(response):
    response.headers.update({
        'Access-Control-Allow-Origin': 'http://127.0.0.1:5501',
        'Access-Control-Allow-Headers': 'Authorization, Range, Content-Type, Accept',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Expose-Headers': 'Content-Range, Accept-Ranges, Content-Length, Content-Type',
        'Access-Control-Max-Age': '3600'
    })

# Tạo JSON response kèm CORS headers


def make_cors_response(data, status):
    response = make_response(jsonify(data), status)
    add_cors_headers(response)
    return response


@stream_bp.route('/video/encrypted/<int:video_id>', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_encrypted_video_by_id(video_id):
    if request.method == 'OPTIONS':
        response = make_response()
        add_cors_headers(response)
        return response

    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return make_cors_response({'error': 'Missing or invalid Authorization token'}, 401)

    token = auth_header.split(' ')[1]

    try:
        cipher = ChaoticCipher.instance_from_token(token)
    except Exception as e:
        logging.error(f"Invalid cipher token: {str(e)}")
        return make_cors_response({'error': 'Invalid encryption token'}, 401)

    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)

        c.execute(
            'SELECT id, title, video_url FROM videos WHERE id = %s', (video_id,))
        video = c.fetchone()

        if not video:
            return make_cors_response({'error': 'Video not found'}, 404)

        headers = {}
        range_header = request.headers.get('Range')
        start_byte = 0
        if range_header:
            headers['Range'] = range_header
            # Parse start byte từ Range header
            match = re.search(r'bytes=(\d+)-', range_header)
            if match:
                start_byte = int(match.group(1))
                logging.info(f"Range request từ byte {start_byte}")

        supabase_response = requests.get(
            video['video_url'], headers=headers, stream=True)

        if supabase_response.status_code not in [200, 206]:
            logging.error(
                f"Supabase error: {supabase_response.status_code} {supabase_response.text}")
            return make_cors_response({'error': 'Unable to retrieve video'}, supabase_response.status_code)

        def generate_encrypted_chunks():
            chunk_count = 0
            current_byte = 0

            # Reset cipher state về đúng vị trí byte bắt đầu
            if start_byte > 0:
                logging.info(f"Reset cipher state về byte {start_byte}")
                # Sinh keystream cho đến vị trí byte bắt đầu
                cipher.generate_keystream_bytes(start_byte)
                current_byte = start_byte

            for chunk in supabase_response.iter_content(chunk_size=1024*1024):
                if chunk:
                    # Log chi tiết cho chunk đầu tiên
                    if chunk_count == 0:
                        logging.info(
                            "=== DEBUG CHUNK ĐẦU TIÊN TRƯỚC KHI MÃ HÓA ===")
                        logging.info(f"Kích thước chunk: {len(chunk)} bytes")
                        logging.info(f"Vị trí byte hiện tại: {current_byte}")
                        logging.info(
                            f"16 bytes đầu tiên: {' '.join([f'{b:02x}' for b in chunk[:16]])}")

                        # Kiểm tra header MP4
                        if len(chunk) >= 8:
                            box_size = int.from_bytes(chunk[:4], 'big')
                            box_type = chunk[4:8].decode(
                                'ascii', errors='replace')
                            logging.info(f"Box size (big-endian): {box_size}")
                            logging.info(f"Box type: {box_type}")

                            # Log trạng thái cipher
                            logging.info(
                                f"Trạng thái cipher trước khi mã hóa: {cipher.save_state()}")

                            # Sinh và log keystream
                            keystream = cipher.generate_keystream_bytes(16)
                            logging.info(
                                f"16 bytes đầu keystream: {' '.join([f'{b:02x}' for b in keystream])}")

                            # Log dữ liệu sau khi mã hóa
                            encrypted = cipher.encrypt(chunk[:16])
                            logging.info(
                                f"16 bytes đầu sau khi mã hóa: {' '.join([f'{b:02x}' for b in encrypted])}")

                            # Log dữ liệu sau khi giải mã (để kiểm tra)
                            decrypted = cipher.decrypt(encrypted)
                            logging.info(
                                f"16 bytes đầu sau khi giải mã: {' '.join([f'{b:02x}' for b in decrypted])}")

                            # Kiểm tra box size và type sau khi giải mã
                            if len(decrypted) >= 8:
                                box_size_dec = int.from_bytes(
                                    decrypted[:4], 'big')
                                box_type_dec = decrypted[4:8].decode(
                                    'ascii', errors='replace')
                                logging.info(
                                    f"Box size sau giải mã: {box_size_dec}")
                                logging.info(
                                    f"Box type sau giải mã: {box_type_dec}")

                        logging.info("=== END DEBUG ===")

                    # Mã hóa chunk
                    encrypted_chunk = cipher.encrypt_with_hash(chunk)
                    chunk_count += 1
                    current_byte += len(chunk)
                    yield encrypted_chunk

        response = Response(
            stream_with_context(generate_encrypted_chunks()),
            status=supabase_response.status_code,
            mimetype='application/octet-stream'  # Đổi mimetype để tránh browser tự xử lý
        )

        response.headers['X-Content-Type'] = 'video/mp4'
        response.headers['X-Encrypted'] = 'true'
        response.headers['Accept-Ranges'] = 'bytes'
        # Thêm header để frontend biết vị trí bắt đầu
        response.headers['X-Start-Byte'] = str(start_byte)

        if 'Content-Range' in supabase_response.headers:
            response.headers['Content-Range'] = supabase_response.headers['Content-Range']

        if 'Content-Length' in supabase_response.headers:
            response.headers['Content-Length'] = supabase_response.headers['Content-Length']

        add_cors_headers(response)
        return response

    except Exception as e:
        logging.error(f"Error during video encryption: {str(e)}")
        return make_cors_response({'error': str(e)}, 500)

    finally:
        if 'conn' in locals():
            conn.close()
