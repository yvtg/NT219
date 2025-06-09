from typing import Dict
import os
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

# Tham số mã hóa hỗn loạn
CHAOTIC_PARAMS: Dict[str, float] = {
    'alpha': float(os.getenv('CHAOTIC_ALPHA', '3.99')),
    'beta': float(os.getenv('CHAOTIC_BETA', '0.01')),
    'gamma': float(os.getenv('CHAOTIC_GAMMA', '0.005')),
    'x0': float(os.getenv('CHAOTIC_X0', '0.678')),
    'y0': float(os.getenv('CHAOTIC_Y0', '0.123')),
    'z0': float(os.getenv('CHAOTIC_Z0', '0.654'))
}

# Số vòng lặp warm-up
WARMUP_ITERATIONS = 1000

# Kích thước chunk mặc định (500KB)
CHUNK_SIZE = 512 * 1024

# Thư mục chứa video
VIDEOS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'videos')
