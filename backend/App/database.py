import psycopg2
from psycopg2.extras import RealDictCursor
import os

def get_db_connection():
    """Tạo kết nối đến Neon PostgreSQL sử dụng DATABASE_URL"""
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        raise ValueError("DATABASE_URL not set in environment variables")
    return psycopg2.connect(database_url, cursor_factory=RealDictCursor)

def init_db():
    """Khởi tạo bảng users và videos trong Neon PostgreSQL"""
    conn = get_db_connection()
    c = conn.cursor()
    # Bảng users (giữ nguyên)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        verified INTEGER DEFAULT 0,
        last_ip TEXT,
        verification_token TEXT
    )''')
    # Bảng videos
    c.execute('''CREATE TABLE IF NOT EXISTS videos (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        thumbnail_url TEXT,
        video_url TEXT,
        category TEXT,
        is_featured BOOLEAN DEFAULT FALSE
    )''')
    # Tạo index
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_videos_category ON videos(category)')
    conn.commit()
    conn.close()