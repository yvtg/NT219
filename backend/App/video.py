import os
from flask import Blueprint, jsonify, request, send_file, send_from_directory
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required
from .database import get_db_connection
from psycopg2.extras import RealDictCursor
import logging

videos_bp = Blueprint('videos', __name__)

@videos_bp.route('/videos', methods=['POST'])
@jwt_required()
def add_video():
    """
    Add a new video
    ---
    tags:
      - Videos
    parameters:
      - in: body
        name: body
        required: true
        schema:
          id: Video
          required:
            - title
            - video_url
            - thumbnail_url
            - category
          properties:
            title:
              type: string
            video_url:
              type: string
            thumbnail_url:
              type: string
            category:
              type: string
    responses:
      201:
        description: Video added successfully
      403:
        description: Unauthorized
    """
    claims = get_jwt()
    if claims.get('role') != 'production':
        return jsonify({'message': 'Unauthorized'}), 403
    data = request.get_json()
    title = data.get('title')
    video_url = data.get('video_url')
    thumbnail_url = data.get('thumbnail_url')
    category = data.get('category')

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        'INSERT INTO videos (title, video_url, thumbnail_url, category) VALUES (%s, %s, %s, %s) RETURNING id',
        (title, video_url, thumbnail_url, category)
    )
    video_id = c.fetchone()[0]
    conn.commit()
    conn.close()
    return jsonify({'message': 'Video added', 'id': video_id}), 201

# Thêm video mẫu khi khởi tạo (tùy chọn)
@videos_bp.route('/init_videos', methods=['POST'])
@jwt_required()
def init_videos():
    """
    Initialize sample videos (Admin only)
    ---
    tags:
      - Videos
    security:
      - Bearer: []
    responses:
      200:
        description: Videos initialized
      403:
        description: Insufficient permissions
    """
    from .security import role_required
    role_required('admin')

    conn = get_db_connection()
    c = conn.cursor()
    sample_videos = [
        ('Phim hành động 1', 'Hành động bùng nổ', '/api/placeholder/300/169?text=1', 'video1.mp4', 'popular', True),
        ('Phim hài 2', 'Hài hước', '/api/placeholder/300/169?text=2', 'video2.mp4', 'popular', False),
        ('Phim tình cảm 3', 'Lãng mạn', '/api/placeholder/300/169?text=3', 'video3.mp4', 'popular', False),
        ('Series hấp dẫn 1', 'Xu hướng', '/api/placeholder/300/169?text=Trend1', 'trend1.mp4', 'trending', False),
        ('Phim đã xem 1', 'Xem lại', '/api/placeholder/300/169?text=Rewatch1', 'rewatch1.mp4', 'rewatch', False),
    ]
    for title, desc, thumb, video, cat, feat in sample_videos:
        c.execute(
            'INSERT INTO videos (title, description, thumbnail_url, video_url, category, is_featured) VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING',
            (title, desc, thumb, video, cat, feat)
        )
    conn.commit()
    conn.close()
    logging.info("Sample videos initialized")
    return jsonify({'message': 'Videos initialized'}), 200

@videos_bp.route('/')
def serve_index():
    """
    Serve static files (CSS, JS, images, etc.) from the frontend directory.
    ---
    tags:
      - Static
    summary: Serve static file
    parameters:
      - name: filename
        in: path
        type: string
        required: true
        description: The path to the static file.
    responses:
      200:
        description: Static file returned successfully.
      404:
        description: File not found.
    """
    return send_from_directory('../frontend', 'index.html')


@videos_bp.route('/<path:filename>')
def serve_static_files(filename):
    """
    Serve static files from frontend directory.

    ---
    tags:
      - Static Files
    summary: Serve a file from the frontend directory by filename/path
    parameters:
      - name: filename
        in: path
        type: string
        required: true
        description: Relative path to the file inside frontend folder, e.g. 'video/public_key.pem'
    responses:
      200:
        description: File successfully served
        content:
          application/octet-stream:
            schema:
              type: string
              format: binary
      404:
        description: File not found
    """
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'frontend/video'))
    print(f"Serving file: {filename} from directory: {frontend_dir}")
    return send_from_directory(frontend_dir, filename)


@videos_bp.route('/get-key')
def get_hls_key():
    """
    Provide the digital signature file of the protected video.
    ---
    tags:
      - Secure Video Access
    summary: Get video digital signature
    security:
      - BearerAuth: []
    responses:
      200:
        description: Digital signature file (video.sig) sent successfully.
        content:
          application/octet-stream:
            schema:
              type: string
              format: binary
      401:
        description: Unauthorized access.
    """
    key_path = os.path.join(os.path.dirname(__file__), '..','..', 'media', 'enc.key')
    return send_file(key_path)


@videos_bp.route('/get-signature')
def get_signature():
    """
    Provide the digital signature file associated with the protected video.

    Only accessible to authenticated users via JWT.

    Returns:
        flask.Response: The digital signature file (`video.sig`) for download.
    """
    print("Gửi file chữ ký số...")
    sig_path = os.path.join(os.path.dirname(__file__), '..','..', 'frontend', 'video', 'video.sig')
    return send_file(sig_path, as_attachment=True)


@videos_bp.route('/get-public-key')
def get_public_key():
    """
    Provide the public key for verifying the digital signature.
    ---
    tags:
      - Secure Video Access
    summary: Get public key
    security:
      - BearerAuth: []
    responses:
      200:
        description: Public key (PEM format) returned.
        content:
          application/x-pem-file:
            schema:
              type: string
              format: binary
      401:
        description: Unauthorized access.
    """
    print("Gửi file public key...")
    key_path = os.path.join(os.path.dirname(__file__), '..','..', 'frontend', 'video', 'public_key.pem')
    return send_file(key_path, as_attachment=True)