import numpy as np
from typing import Dict, List, Tuple
import hashlib
import hmac
import logging


class ChaoticCipher:
    # Đồng bộ với JavaScript: INT_SCALE = 1e14
    INT_SCALE = 10**14

    def __init__(self, alpha=3.9, beta=0.01, gamma=0.005, x0=0.1, y0=0.2, z0=0.3, warmup_iterations=1000):
        # Lưu các tham số
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.warmup_iterations = warmup_iterations

        # Chuyển đổi tham số và trạng thái ban đầu sang số nguyên lớn
        self._alpha_int = int(alpha * ChaoticCipher.INT_SCALE)
        self._beta_int = int(beta * ChaoticCipher.INT_SCALE)
        self._gamma_int = int(gamma * ChaoticCipher.INT_SCALE)

        # Trạng thái hiện tại dưới dạng số nguyên lớn
        self._x_int = int(x0 * ChaoticCipher.INT_SCALE)
        self._y_int = int(y0 * ChaoticCipher.INT_SCALE)
        self._z_int = int(z0 * ChaoticCipher.INT_SCALE)

        self.isInitialized = False
        self.warmup(self.warmup_iterations)
        self.isInitialized = True

    @classmethod
    def instance_from_token(cls, token: str):
        """
        Tạo instance từ csrf_token 
        """
        # Nếu token là hex -> bytes
        try:
            token_bytes = bytes.fromhex(token)
        except ValueError:
            # Không phải hex, cứ encode bình thường
            token_bytes = token.encode()

        # Băm SHA-256
        token_hash = hashlib.sha256(token_bytes).digest()

        # Sử dụng 32 byte đầu tiên của hash (đủ cho 6 giá trị 64-bit hoặc nhiều hơn)
        # Chúng ta sẽ chia 32 byte này thành 6 phần để sinh 6 tham số/trạng thái

        def bytes_to_float(byte_slice):
            # Chuyển một lát cắt byte thành một số nguyên, sau đó chuẩn hóa về khoảng [0, 1)
            # Sử dụng int.from_bytes với byteorder='big' để đảm bảo nhất quán
            int_val = int.from_bytes(byte_slice, 'big')
            # Chuẩn hóa về khoảng [0, 1) bằng cách chia cho giá trị lớn nhất có thể
            # Giá trị lớn nhất cho một lát cắt 5 byte là 2**(5*8) - 1 = 2**40 - 1
            max_val = 2**(len(byte_slice)*8) - 1
            return int_val / max_val if max_val > 0 else 0.0

        # Chia hash 32 byte thành 6 phần (ví dụ: 5 byte mỗi phần, còn dư)
        slice_size = 5  # 5 * 8 = 40 bits

        # Sinh x0, y0, z0 (trong khoảng (0, 1) để tránh điểm cố định)
        # Bỏ qua giá trị 0.0 và 1.0 nếu có thể
        x0 = bytes_to_float(token_hash[0*slice_size: 1*slice_size])
        y0 = bytes_to_float(token_hash[1*slice_size: 2*slice_size])
        z0 = bytes_to_float(token_hash[2*slice_size: 3*slice_size])

        # Đảm bảo x0, y0, z0 không quá gần 0 hoặc 1
        min_initial = 1e-6
        max_initial = 1.0 - 1e-6
        x0 = max(min(x0, max_initial), min_initial)
        y0 = max(min(y0, max_initial), min_initial)
        z0 = max(min(z0, max_initial), min_initial)

        # Sinh alpha, beta, gamma
        # alpha thường trong khoảng (3.57, 4.0) cho hỗn loạn mạnh
        # beta, gamma thường là các giá trị nhỏ

        # Sử dụng các phần còn lại của hash cho alpha, beta, gamma
        alpha_raw = bytes_to_float(token_hash[3*slice_size: 4*slice_size])
        beta_raw = bytes_to_float(token_hash[4*slice_size: 5*slice_size])
        gamma_raw = bytes_to_float(
            token_hash[5*slice_size: 6*slice_size])  # Lấy 2 byte cuối

        # Ánh xạ raw values vào khoảng tham số mong muốn
        # alpha từ (3.57 + alpha_raw * 0.43) -> (3.57, 4.0)
        # beta, gamma từ (0.001 + raw * 0.01) -> (0.001, 0.011)

        alpha = 3.57 + alpha_raw * (4.0 - 3.57)
        beta = 0.001 + beta_raw * 0.01
        gamma = 0.001 + gamma_raw * 0.01

        # Sinh số vòng warm-up từ hash (ví dụ: 1000 + int từ hash % 1000)
        warmup_seed_int = int.from_bytes(
            token_hash[-4:], 'big')  # 4 byte cuối
        warmup_iterations = 1000 + (warmup_seed_int %
                                    1000)  # Khoảng 1000 - 1999

        # Tạo instance ChaoticCipher với các tham số đã sinh
        # Constructor sẽ tự động thực hiện warm-up
        instance = cls(alpha=alpha, beta=beta, gamma=gamma, x0=x0,
                       y0=y0, z0=z0, warmup_iterations=warmup_iterations)

        instance._keystream_key = hashlib.sha256(
            b'keystream|' + token_bytes).digest()
        instance._auth_key = hashlib.sha256(
            b'auth|' + token_bytes).digest()
        return instance

    def _logistic_map_3d_int(self):
        # Đồng bộ với JavaScript: sử dụng cùng công thức và phép tính
        ONE_INT = ChaoticCipher.INT_SCALE

        x_int = self._x_int
        y_int = self._y_int
        z_int = self._z_int

        # Sử dụng phép chia nguyên // thay vì / để đồng bộ với JavaScript
        # x(n+1) = alpha * x * (1-x) + beta * y * z
        term1_x = (self._alpha_int * x_int *
                   (ONE_INT - x_int)) // (ONE_INT * ONE_INT)
        term2_x = (self._beta_int * y_int * z_int) // ONE_INT
        x_new_int = term1_x + term2_x

        # y(n+1) = alpha * y * (1-y) + beta * x * z
        term1_y = (self._alpha_int * y_int *
                   (ONE_INT - y_int)) // (ONE_INT * ONE_INT)
        term2_y = (self._beta_int * x_int * z_int) // ONE_INT
        y_new_int = term1_y + term2_y

        # z(n+1) = alpha * z * (1-z) + gamma * x * y
        term1_z = (self._alpha_int * z_int *
                   (ONE_INT - z_int)) // (ONE_INT * ONE_INT)
        term2_z = (self._gamma_int * x_int * y_int) // ONE_INT
        z_new_int = term1_z + term2_z

        # Chuẩn hóa lại kết quả về khoảng [0, INT_SCALE)
        # Thêm phép dịch bit để tăng tính ngẫu nhiên
        self._x_int = ((x_new_int % ONE_INT) + ONE_INT) % ONE_INT
        self._y_int = ((y_new_int % ONE_INT) + ONE_INT) % ONE_INT
        self._z_int = ((z_new_int % ONE_INT) + ONE_INT) % ONE_INT

        # Đảm bảo không có giá trị 0
        if self._x_int == 0:
            self._x_int = ONE_INT // 2
        if self._y_int == 0:
            self._y_int = ONE_INT // 3
        if self._z_int == 0:
            self._z_int = ONE_INT // 4

    def _generate_byte_int(self):
        # Sinh một byte từ trạng thái hiện tại (dạng số nguyên lớn)
        self._logistic_map_3d_int()  # Cập nhật trạng thái dùng hàm số nguyên

        # Kết hợp 3 giá trị int (trong khoảng [0, INT_SCALE))
        # Lấy các bit từ các phần khác nhau của số nguyên lớn
        # Ví dụ: Lấy 8 byte (64 bit) từ mỗi số int_scale
        # Sử dụng phép dịch bit và XOR

        # Lấy 64 bit cuối của mỗi số nguyên lớn
        mask_64_bit = (1 << 64) - 1
        x64 = self._x_int & mask_64_bit
        y64 = self._y_int & mask_64_bit
        z64 = self._z_int & mask_64_bit

        # Kết hợp 3 giá trị 64-bit bằng XOR và dịch bit
        # Thêm phép dịch bit để tăng tính ngẫu nhiên
        combined_64 = (x64 ^ (y64 << 1) ^ (z64 >> 1)) & mask_64_bit

        # Lấy 8 bit cuối làm 1 byte keystream
        # Thêm phép dịch bit để tránh số 0
        keystream_byte = ((combined_64 & 0xFF) ^ (
            (combined_64 >> 8) & 0xFF)) & 0xFF
        if keystream_byte == 0:
            keystream_byte = 0xFF  # Đảm bảo không sinh ra số 0

        return keystream_byte

    def warmup(self, iterations):
        """
        Thực hiện warm-up N vòng để hệ vào trạng thái ổn định hơn.
        Sử dụng hàm tính toán số nguyên.
        """
        for _ in range(iterations):
            self._logistic_map_3d_int()  # Dùng hàm số nguyên

    def generate_keystream_bytes(self, num_bytes):
        """
        Sinh ra một lượng keystream byte nhất định và cập nhật trạng thái cipher.
        Sử dụng hàm sinh byte số nguyên.

        Args:
            num_bytes: Số byte keystream cần sinh.

        Returns:
            bytes: Lượng keystream đã sinh.
        """
        if not self.isInitialized:
            # Điều này không nên xảy ra nếu instance được tạo qua from_password
            # vì from_password đã gọi warm-up và set isInitialized.
            # Tuy nhiên, thêm kiểm tra phòng hờ.
            print(
                "Warning: ChaoticCipher not initialized when calling generate_keystream_bytes.")
            # Có thể raise Exception hoặc thực hiện warm-up ở đây nếu thiết kế cho phép
            # raise Exception("ChaoticCipher not initialized.")
            pass  # Tạm thời bỏ qua để không lỗi nếu luồng gọi chưa đúng hoàn toàn

        keystream = bytearray(num_bytes)
        for i in range(num_bytes):
            # Dùng hàm sinh byte số nguyên
            keystream[i] = self._generate_byte_int()
        return bytes(keystream)

    def encrypt(self, data: bytes) -> bytes:
        """
        Mã hóa dữ liệu bằng XOR với keystream được sinh liên tục.

        Args:
            data: Dữ liệu cần mã hóa (bytes)

        Returns:
            bytes: Dữ liệu đã mã hóa
        """
        # Sinh keystream cho lượng data cần mã hóa từ trạng thái hiện tại
        keystream = self.generate_keystream_bytes(len(data))

        # Mã hóa từng byte
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ keystream[i]

        return bytes(result)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Giải mã dữ liệu bằng XOR với keystream được sinh liên tục.
        (Giống với encrypt vì XOR có tính chất đối xứng)

        Args:
            encrypted_data: Dữ liệu đã mã hóa (bytes)

        Returns:
            bytes: Dữ liệu đã giải mã
        """
        # Sinh keystream cho lượng data cần giải mã từ trạng thái hiện tại
        keystream = self.generate_keystream_bytes(len(encrypted_data))

        # Giải mã từng byte (thực hiện XOR)
        result = bytearray(len(encrypted_data))
        for i in range(len(encrypted_data)):
            result[i] = encrypted_data[i] ^ keystream[i]

        return bytes(result)

    def reset_state_from_token(self, token: str):
        """
        Reset trạng thái chaotic về đúng trạng thái ban đầu từ token.
        """
        new_cipher = ChaoticCipher.instance_from_token(token)
        self._x_int = new_cipher._x_int
        self._y_int = new_cipher._y_int
        self._z_int = new_cipher._z_int
        self._alpha_int = new_cipher._alpha_int
        self._beta_int = new_cipher._beta_int
        self._gamma_int = new_cipher._gamma_int
        self.isInitialized = True

    def save_state(self) -> Tuple[int, int, int]:
        """
        Lưu trạng thái hiện tại (x, y, z) dưới dạng INT.
        """
        return (self._x_int, self._y_int, self._z_int)

    def load_state(self, state: Tuple[int, int, int]):
        """
        Khôi phục trạng thái từ giá trị đã lưu.
        """
        self._x_int, self._y_int, self._z_int = state

    def encrypt_with_hash(self, data: bytes) -> bytes:
        """
        Mã hóa dữ liệu + gắn SHA256 hash + HMAC.
        """
        # Log keystream cho chunk đầu tiên
        if not hasattr(self, '_last_chunk_size') or self._last_chunk_size != len(data):
            logging.info("Debug keystream cho chunk mới:")
            logging.info(f"Kích thước chunk: {len(data)} bytes")
            keystream = self.generate_keystream_bytes(8)  # Lấy 8 byte đầu
            logging.info(
                f"8 bytes đầu keystream: {' '.join([f'{b:02x}' for b in keystream])}")
            logging.info(f"Trạng thái cipher: {self.save_state()}")
            self._last_chunk_size = len(data)

        # Tính hash SHA256 của dữ liệu
        data_hash = hashlib.sha256(data).digest()

        # Mã hóa dữ liệu + hash gốc
        payload = data + data_hash
        encrypted = self.encrypt(payload)

        tag = hmac.new(self._auth_key, encrypted, hashlib.sha256).digest()
        return encrypted + tag

    def decrypt_with_hash(self, encrypted_data: bytes) -> bytes:
        """
        Giải mã + xác minh toàn vẹn bằng SHA256 và HMAC.
        """
        if len(encrypted_data) < 32 + 32:
            raise ValueError("Dữ liệu không hợp lệ hoặc thiếu tag.")

        if not hasattr(self, '_auth_key'):
            raise ValueError(
                "⚠️ Chưa có khóa xác thực!")

        # Tách dữ liệu
        tag = encrypted_data[-32:]
        ciphertext = encrypted_data[:-32]

        # Kiểm tra HMAC
        expected_tag = hmac.new(
            self._auth_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            print("‼️ HMAC mismatch!")
            print("Expected:", expected_tag.hex())
            print("Received:", tag.hex())
            raise ValueError(
                "❌ Dữ liệu bị thay đổi hoặc tag không hợp lệ (HMAC sai)")

        # Giải mã
        decrypted = self.decrypt(ciphertext)

        # Tách phần gốc và hash
        data, data_hash = decrypted[:-32], decrypted[-32:]
        actual_hash = hashlib.sha256(data).digest()

        # Kiểm tra hash toàn vẹn
        if actual_hash != data_hash:
            print("‼️ Hash mismatch!")
            print("Expected:", data_hash.hex())
            print("Actual  :", actual_hash.hex())
            raise ValueError("❌ Dữ liệu bị thay đổi hoặc hash sai!")

        return data
