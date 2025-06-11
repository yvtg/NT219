import os
import base64 
import uuid 
from io import BytesIO 
from flask import Blueprint, jsonify, request, send_file, send_from_directory
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required
from .database import get_db_connection
from psycopg2.extras import RealDictCursor
from Crypto.Cipher import AES 
from .storage import upload_file, download_file, get_public_url
import logging

videos_bp = Blueprint('videos', __name__)

@videos_bp.route('/videos/upload_aes', methods=['POST'])
@jwt_required()
def upload_video_aes():
    """Upload a video, encrypt with AES-GCM and store to Supabase (admin only)."""
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'message': 'Insufficient permissions'}), 403

    if 'file' not in request.files:
        return jsonify({'message': 'Missing file'}), 400

    file = request.files['file']
    title = request.form.get('title') or file.filename
    description = request.form.get('description', '')
    category = request.form.get('category', '')
    thumbnail_url = request.form.get('thumbnail_url', '')
    is_featured = request.form.get('is_featured', 'false').lower() == 'true'

    data = file.read()
    key = os.urandom(32)
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted = ciphertext + tag

    file_path = f"{uuid.uuid4()}.bin"
    upload_file(file_path, encrypted)

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        'INSERT INTO videos (title, description, thumbnail_url, video_url, category, is_featured, aes_key, aes_iv) '
        'VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id',
        (title, description, thumbnail_url, file_path, category, is_featured,
         base64.b64encode(key).decode(), base64.b64encode(iv).decode())
    )
    video_id = c.fetchone()[0]
    conn.commit()
    conn.close()

    url = get_public_url(file_path)
    return jsonify({'id': video_id, 'url': url}), 201


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
            description:
              type: string
            is_featured:
              type: boolean
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
    description = data.get('description', '')
    is_featured = data.get('is_featured', False)

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        'INSERT INTO videos (title, description, thumbnail_url, video_url, category, is_featured) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id',
        (title, description, thumbnail_url, video_url, category, is_featured)
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
        ('Phim hành động 1', 'Hành động bùng nổ',
         '/api/placeholder/300/169?text=1', 'video1.mp4', 'popular', True),
        ('Phim hài 2', 'Hài hước', '/api/placeholder/300/169?text=2',
         'video2.mp4', 'popular', False),
        ('Phim tình cảm 3', 'Lãng mạn', '/api/placeholder/300/169?text=3',
         'video3.mp4', 'popular', False),
        ('Series hấp dẫn 1', 'Xu hướng', '/api/placeholder/300/169?text=Trend1',
         'trend1.mp4', 'trending', False),
        ('Phim đã xem 1', 'Xem lại', '/api/placeholder/300/169?text=Rewatch1',
         'rewatch1.mp4', 'rewatch', False),
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
    frontend_dir = os.path.abspath(os.path.join(
        os.path.dirname(__file__), '..', '..', 'frontend/video'))
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
    key_path = os.path.join(os.path.dirname(__file__),
                            '..', '..', 'media', 'enc.key')
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
    sig_path = os.path.join(os.path.dirname(__file__),
                            '..', '..', 'frontend', 'video', 'video.sig')
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
    key_path = os.path.join(os.path.dirname(__file__),
                            '..', '..', 'frontend', 'video', 'public_key.pem')
    return send_file(key_path, as_attachment=True)

@videos_bp.route('/videos/aes/<int:video_id>')
@jwt_required()
def stream_aes_video(video_id):
    """Retrieve encrypted video from Supabase, decrypt and stream."""
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute('SELECT video_url, aes_key, aes_iv FROM videos WHERE id = %s', (video_id,))
    video = c.fetchone()
    conn.close()
    if not video:
        return jsonify({'message': 'Video not found'}), 404

    # Kiểm tra xem video có được mã hóa không
    if not video['aes_key'] or not video['aes_iv']:
        return jsonify({'message': 'Video not encrypted or missing encryption keys'}), 400

    try:
        data = download_file(video['video_url'])
        key = base64.b64decode(video['aes_key'])
        iv = base64.b64decode(video['aes_iv'])
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = data[:-16], data[-16:]
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return send_file(BytesIO(plaintext), mimetype='video/mp4')
    except Exception as e:
        logging.error(f"Error streaming video {video_id}: {str(e)}")
        return jsonify({'message': 'Error streaming video'}), 500

@videos_bp.route('/videos', methods=['GET'])
@jwt_required()
def get_videos():
    """
    Get list of videos
    ---
    tags:
      - Videos
    security:
      - Bearer: []
    responses:
      200:
        description: List of videos
    """
    try:
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT id, title, description, thumbnail_url, video_url, category, is_featured, created_at FROM videos ORDER BY created_at DESC')
        videos = c.fetchall()
        conn.close()
        return jsonify(videos), 200
    except Exception as e:
        logging.error(f"Error fetching videos: {str(e)}")
        return jsonify({'message': 'Failed to fetch videos'}), 500

@videos_bp.route('/videos/clear-test', methods=['POST'])
@jwt_required()
def clear_test_videos():
    """
    Clear test videos and create a sample encrypted video
    ---
    tags:
      - Videos
    security:
      - Bearer: []
    responses:
      200:
        description: Test videos cleared and sample created
    """
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'message': 'Insufficient permissions'}), 403
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        # Xóa tất cả video cũ
        c.execute('DELETE FROM videos')
        
        # Tạo một video test với encryption
        test_data = b"This is a test video content for encryption demonstration."
        key = os.urandom(32)
        iv = os.urandom(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(test_data)
        encrypted = ciphertext + tag
        
        file_path = f"test_video_{uuid.uuid4()}.bin"
        upload_file(file_path, encrypted)
        
        # Lưu vào database với đầy đủ thông tin
        c.execute(
            'INSERT INTO videos (title, description, thumbnail_url, video_url, category, is_featured, aes_key, aes_iv) '
            'VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id',
            ('Video Test Mã Hóa', 'Video test để demo mã hóa AES-GCM', '/api/placeholder/300/169?text=Test', file_path, 'test', True,
             base64.b64encode(key).decode(), base64.b64encode(iv).decode())
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Test videos cleared and sample encrypted video created'}), 200
    except Exception as e:
        logging.error(f"Error clearing test videos: {str(e)}")
        return jsonify({'message': 'Failed to clear test videos'}), 500

@videos_bp.route('/local-storage/<path:filename>')
def serve_local_storage(filename):
    """
    Serve files from local storage
    ---
    tags:
      - Local Storage
    parameters:
      - name: filename
        in: path
        type: string
        required: true
        description: The filename in local storage
    responses:
      200:
        description: File served successfully
      404:
        description: File not found
    """
    try:
        from .storage import LOCAL_STORAGE_DIR
        file_path = os.path.join(LOCAL_STORAGE_DIR, filename)
        
        if not os.path.exists(file_path):
            return jsonify({'message': 'File not found'}), 404
        
        return send_file(file_path, as_attachment=False)
    except Exception as e:
        logging.error(f"Error serving local file {filename}: {str(e)}")
        return jsonify({'message': 'Error serving file'}), 500
