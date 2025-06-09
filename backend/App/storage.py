from supabase import create_client
import os
from dotenv import load_dotenv

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


def get_public_url(file_path, bucket_name="videos"):
    url = supabase.storage.from_(bucket_name).get_public_url(file_path)
    return url
