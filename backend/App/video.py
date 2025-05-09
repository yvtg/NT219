from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from .database import get_db_connection
from psycopg2.extras import RealDictCursor
import logging

videos_bp = Blueprint('videos', __name__)

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
    parameters:
      - name: category
        in: query
        type: string
        description: Filter by category (e.g., popular, trending, rewatch)
      - name: limit
        in: query
        type: integer
        description: Number of items to return
    responses:
      200:
        description: List of videos
      401:
        description: Unauthorized
    """
    category = request.args.get('category', 'popular')
    limit = request.args.get('limit', 6, type=int)

    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute(
        'SELECT id, title, description, thumbnail_url, video_url FROM videos WHERE category = %s LIMIT %s',
        (category, limit)
    )
    videos = c.fetchall()
    conn.close()

    return jsonify({'videos': videos}), 200

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