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
    """Khởi tạo bảng users trong Neon PostgreSQL"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        verified INTEGER DEFAULT 0,
        phone TEXT,
        last_ip TEXT
    )''')
    # Tạo index để tối ưu truy vấn
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    conn.commit()
    conn.close()