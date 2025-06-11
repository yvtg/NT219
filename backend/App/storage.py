from supabase import create_client
import os
from dotenv import load_dotenv
import logging
import tempfile
import shutil

load_dotenv(dotenv_path='D:\\NT219\\NT219\\backend\\config\\.env')

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

# Sử dụng service role key nếu có, nếu không thì dùng anon key
SUPABASE_SERVICE_KEY = os.getenv('SUPABASE_SERVICE_KEY')
SUPABASE_KEY_TO_USE = SUPABASE_SERVICE_KEY if SUPABASE_SERVICE_KEY else SUPABASE_KEY

# Fallback sang local storage nếu Supabase không hoạt động
USE_LOCAL_STORAGE = os.getenv('USE_LOCAL_STORAGE', 'false').lower() == 'true'

# Thư mục local storage
LOCAL_STORAGE_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'local_storage')
os.makedirs(LOCAL_STORAGE_DIR, exist_ok=True)

if not USE_LOCAL_STORAGE and (not SUPABASE_URL or not SUPABASE_KEY_TO_USE):
    print("⚠️  Supabase credentials not found, falling back to local storage")
    USE_LOCAL_STORAGE = True

if not USE_LOCAL_STORAGE:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY_TO_USE)


def get_public_url(file_path, bucket_name="videos"):
    """Get public URL for a file"""
    if USE_LOCAL_STORAGE:
        return f"/api/local-storage/{file_path}"
    
    try:
        url = supabase.storage.from_(bucket_name).get_public_url(file_path)
        return url
    except Exception as e:
        logging.error(f"Error getting public URL: {str(e)}")
        return None


def upload_file(file_path, data: bytes, bucket_name="videos"):
    """Upload binary data to Storage."""
    if USE_LOCAL_STORAGE:
        # Lưu file vào local storage
        file_full_path = os.path.join(LOCAL_STORAGE_DIR, file_path)
        os.makedirs(os.path.dirname(file_full_path), exist_ok=True)
        
        with open(file_full_path, 'wb') as f:
            f.write(data)
        logging.info(f"Uploaded file to local storage: {file_path}")
        return {"path": file_path}
    
    try:
        # Kiểm tra bucket có tồn tại không
        buckets = supabase.storage.list_buckets()
        bucket_exists = any(bucket.name == bucket_name for bucket in buckets)
        
        if not bucket_exists:
            # Tạo bucket mới nếu chưa tồn tại
            supabase.storage.create_bucket(bucket_name, {"public": True})
            logging.info(f"Created bucket: {bucket_name}")
        
        # Upload file
        result = supabase.storage.from_(bucket_name).upload(
            file_path, 
            data,
            {"content-type": "application/octet-stream"}
        )
        logging.info(f"Uploaded file: {file_path}")
        return result
    except Exception as e:
        logging.error(f"Error uploading file {file_path}: {str(e)}")
        # Fallback to local storage
        print(f"⚠️  Supabase upload failed, falling back to local storage: {str(e)}")
        return upload_file(file_path, data, bucket_name)


def download_file(file_path, bucket_name="videos") -> bytes:
    """Download a file from Storage"""
    if USE_LOCAL_STORAGE:
        # Đọc file từ local storage
        file_full_path = os.path.join(LOCAL_STORAGE_DIR, file_path)
        if not os.path.exists(file_full_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_full_path, 'rb') as f:
            data = f.read()
        return data
    
    try:
        data = supabase.storage.from_(bucket_name).download(file_path).data
        return data
    except Exception as e:
        logging.error(f"Error downloading file {file_path}: {str(e)}")
        raise e


def delete_file(file_path, bucket_name="videos"):
    """Delete a file from Storage"""
    if USE_LOCAL_STORAGE:
        # Xóa file từ local storage
        file_full_path = os.path.join(LOCAL_STORAGE_DIR, file_path)
        if os.path.exists(file_full_path):
            os.remove(file_full_path)
            logging.info(f"Deleted file from local storage: {file_path}")
        return
    
    try:
        supabase.storage.from_(bucket_name).remove([file_path])
        logging.info(f"Deleted file: {file_path}")
    except Exception as e:
        logging.error(f"Error deleting file {file_path}: {str(e)}")
        raise e