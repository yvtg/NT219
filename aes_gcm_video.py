import os
from Crypto.Cipher import AES


def encrypt_video(input_path, output_path, key_path, iv_path):
    """Encrypt a video file using AES-GCM."""
    key = os.urandom(32)  # AES-256
    iv = os.urandom(12)   # Recommended length for GCM nonce

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    with open(output_path, 'wb') as f:
        f.write(ciphertext)
        f.write(tag)

    with open(key_path, 'wb') as f:
        f.write(key)

    with open(iv_path, 'wb') as f:
        f.write(iv)

    print(f"Encrypted {input_path} -> {output_path}")


def decrypt_video(input_path, output_path, key_path, iv_path):
    """Decrypt a video file previously encrypted with AES-GCM."""
    with open(key_path, 'rb') as f:
        key = f.read()

    with open(iv_path, 'rb') as f:
        iv = f.read()

    with open(input_path, 'rb') as f:
        data = f.read()

    ciphertext, tag = data[:-16], data[-16:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f"Decrypted {input_path} -> {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Encrypt or decrypt a video using AES-GCM")
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a video")
    enc_parser.add_argument("input", help="Input video file")
    enc_parser.add_argument("output", help="Output encrypted file")
    enc_parser.add_argument("key", help="Path to save AES key")
    enc_parser.add_argument("iv", help="Path to save nonce")

    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a video")
    dec_parser.add_argument("input", help="Input encrypted file")
    dec_parser.add_argument("output", help="Output decrypted video")
    dec_parser.add_argument("key", help="Path to AES key")
    dec_parser.add_argument("iv", help="Path to nonce")

    args = parser.parse_args()

    if args.command == "encrypt":
        encrypt_video(args.input, args.output, args.key, args.iv)
    else:
        decrypt_video(args.input, args.output, args.key, args.iv)