# NT219/process_video.py

import os
import subprocess

# --- CẤU HÌNH ---
# Đường dẫn đến các công cụ
# Nếu bạn đã thêm vào PATH, có thể để trống, nếu không hãy điền đường dẫn đầy đủ
# Ví dụ: FFMPEG_PATH = "C:/ffmpeg/bin/ffmpeg.exe"
FFMPEG_PATH = "ffmpeg"
OPENSSL_PATH = "openssl"
IMAGEMAGICK_PATH = "magick" # ImageMagick 7+ dùng 'magick', bản cũ dùng 'convert'

# Đường dẫn file và thư mục
MEDIA_DIR = "media"
FRONTEND_VIDEO_DIR = os.path.join("frontend", "video")

# Thông tin thủy vân và khóa
WATERMARK_TEXT = "NT219-UserID-456"
VIDEO_IN = os.path.join(MEDIA_DIR, "video_goc.mp4")
WATERMARK_IMG = os.path.join(MEDIA_DIR, "watermark.png")
VIDEO_WATERMARKED = os.path.join(MEDIA_DIR, "video_watermarked.mp4")

PRIVATE_KEY = "private_key.pem"
PUBLIC_KEY = "public_key.pem"
SIGNATURE_FILE = os.path.join(FRONTEND_VIDEO_DIR, "video.sig") # Đặt signature ở frontend luôn

# Thông tin mã hóa HLS
HLS_KEY_INFO_FILE = os.path.join(MEDIA_DIR, "enc.keyinfo")
HLS_KEY_FILE = os.path.join(MEDIA_DIR, "enc.key")
HLS_PLAYLIST = os.path.join(FRONTEND_VIDEO_DIR, "playlist.m3u8")


def run_command(command):
    """Hàm để chạy lệnh và in kết quả"""
    print(f"--- Đang chạy lệnh: {' '.join(command)}")
    try:
        subprocess.run(command, check=True, shell=True)
        print("--- Lệnh thực thi thành công!")
    except subprocess.CalledProcessError as e:
        print(f"--- LỖI: {e}")
        exit(1)


def main():
    # Tạo các thư mục nếu chưa tồn tại
    os.makedirs(MEDIA_DIR, exist_ok=True)
    os.makedirs(FRONTEND_VIDEO_DIR, exist_ok=True)

    print("=== BƯỚC 1: TẠO KHÓA VÀ THỦY VÂN ===")
    
    # 1.1. Tạo cặp khóa Public/Private
    if not os.path.exists(PRIVATE_KEY):
        run_command([OPENSSL_PATH, "genrsa", "-out", PRIVATE_KEY, "2048"])
        run_command([OPENSSL_PATH, "rsa", "-in", PRIVATE_KEY, "-pubout", "-out", PUBLIC_KEY])
    else:
        print(f"- Đã tìm thấy {PRIVATE_KEY} và {PUBLIC_KEY}, bỏ qua bước tạo khóa.")

    # 1.2. Tạo ảnh thủy vân
    run_command([
        IMAGEMAGICK_PATH, "convert", "-size", "400x50", "xc:transparent", "-fill", "rgba(200,200,200,0.3)",
        "-gravity", "center", "-pointsize", "20", "-annotate", "+0+0", WATERMARK_TEXT, WATERMARK_IMG
    ])

    print("\n=== BƯỚC 2: NHÚNG THỦY VÂN VÀO VIDEO ===")
    run_command([
        FFMPEG_PATH, "-y", "-i", VIDEO_IN, "-i", WATERMARK_IMG,
        "-filter_complex", "[0:v][1:v] overlay=W-w-10:H-h-10:format=auto,format=yuv420p",
        "-c:v", "libx264", "-crf", "23", "-c:a", "copy",
        VIDEO_WATERMARKED
    ])

    print("\n=== BƯỚC 3: TẠO CHỮ KÝ SỐ CHO VIDEO ĐÃ CÓ THỦY VÂN ===")
    run_command([
        OPENSSL_PATH, "dgst", "-sha256", "-sign", PRIVATE_KEY, "-out", SIGNATURE_FILE, VIDEO_WATERMARKED
    ])

    print("\n=== BƯỚC 4: MÃ HÓA VIDEO BẰNG HLS AES-128 ===")
    
    # 4.1. Tạo khóa mã hóa HLS
    run_command([OPENSSL_PATH, "rand", "16", ">", HLS_KEY_FILE])

    # 4.2. Tạo file keyinfo
    # Sửa URL trỏ đến backend Flask của bạn
    key_info_content = f"http://127.0.0.1:8000/api/get-key\n{HLS_KEY_FILE.replace(os.sep, '/')}"
    with open(HLS_KEY_INFO_FILE, "w") as f:
        f.write(key_info_content)

    # 4.3. Chạy lệnh mã hóa HLS
    run_command([
        FFMPEG_PATH, "-y", "-i", VIDEO_WATERMARKED,
        "-c:v", "copy", "-c:a", "copy",
        "-hls_time", "10",
        "-hls_list_size", "0",
        "-hls_key_info_file", HLS_KEY_INFO_FILE,
        HLS_PLAYLIST
    ])
    
    # Copy file public key vào thư mục frontend để dễ dàng tải về
    run_command(["copy" if os.name == 'nt' else 'cp', PUBLIC_KEY, os.path.join(FRONTEND_VIDEO_DIR, "public_key.pem")])

    print("\n=== HOÀN TẤT! ===")
    print(f"Video đã được mã hóa và sẵn sàng tại: {FRONTEND_VIDEO_DIR}")
    print(f"Chữ ký số: {SIGNATURE_FILE}")
    print(f"Public key: {os.path.join(FRONTEND_VIDEO_DIR, 'public_key.pem')}")


if __name__ == "__main__":
    main()