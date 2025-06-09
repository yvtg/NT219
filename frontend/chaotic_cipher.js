/**
 * Class ChaoticCipher - Xử lý mã hóa/giải mã sử dụng Logistic Map 3D
 * Đảm bảo đồng bộ keystream giữa client và server
 */
// Đồng bộ với Python: INT_SCALE = 10**14
const INT_SCALE = 1e14;

class ChaoticCipher {
    constructor(alpha = 3.9, beta = 0.01, gamma = 0.005, x0 = 0.1, y0 = 0.2, z0 = 0.3, warmup_iterations = 1000) {
        // Lưu các tham số
        this.alpha = alpha;
        this.beta = beta;
        this.gamma = gamma;
        this.warmup_iterations = warmup_iterations;

        // Chuyển đổi tham số và trạng thái ban đầu sang số nguyên lớn
        this._alpha_int = Math.floor(alpha * INT_SCALE);
        this._beta_int = Math.floor(beta * INT_SCALE);
        this._gamma_int = Math.floor(gamma * INT_SCALE);

        // Trạng thái hiện tại dưới dạng số nguyên lớn
        this._x_int = Math.floor(x0 * INT_SCALE);
        this._y_int = Math.floor(y0 * INT_SCALE);
        this._z_int = Math.floor(z0 * INT_SCALE);

        this.isInitialized = false;
        this.warmup(warmup_iterations);
        this.isInitialized = true;
    }

    static async instanceFromToken(token) {
        // Chuyển token thành bytes
        let tokenBytes;
        try {
            // Thử parse hex
            tokenBytes = new Uint8Array(token.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        } catch {
            // Nếu không phải hex, encode bình thường
            tokenBytes = new TextEncoder().encode(token);
        }

        // Băm SHA-256
        const tokenHash = await crypto.subtle.digest('SHA-256', tokenBytes);

        // Hàm chuyển bytes thành float trong khoảng [0,1)
        const bytesToFloat = (byteSlice) => {
            const intVal = BigInt('0x' + Array.from(byteSlice)
                .map(b => b.toString(16).padStart(2, '0'))
                .join(''));
            const maxVal = BigInt(2) ** BigInt(byteSlice.length * 8) - BigInt(1);
            return Number(intVal) / Number(maxVal);
        };

        // Chia hash 32 byte thành 6 phần
        const sliceSize = 5; // 5 * 8 = 40 bits
        const hashArray = new Uint8Array(tokenHash);

        // Sinh x0, y0, z0 trong khoảng (0,1)
        let x0 = bytesToFloat(hashArray.slice(0 * sliceSize, 1 * sliceSize));
        let y0 = bytesToFloat(hashArray.slice(1 * sliceSize, 2 * sliceSize));
        let z0 = bytesToFloat(hashArray.slice(2 * sliceSize, 3 * sliceSize));

        // Đảm bảo x0, y0, z0 không quá gần 0 hoặc 1
        const minInitial = 1e-6;
        const maxInitial = 1.0 - 1e-6;
        x0 = Math.max(Math.min(x0, maxInitial), minInitial);
        y0 = Math.max(Math.min(y0, maxInitial), minInitial);
        z0 = Math.max(Math.min(z0, maxInitial), minInitial);

        // Sinh alpha, beta, gamma
        const alphaRaw = bytesToFloat(hashArray.slice(3 * sliceSize, 4 * sliceSize));
        const betaRaw = bytesToFloat(hashArray.slice(4 * sliceSize, 5 * sliceSize));
        const gammaRaw = bytesToFloat(hashArray.slice(5 * sliceSize, 6 * sliceSize));

        // Ánh xạ raw values vào khoảng tham số mong muốn
        const alpha = 3.57 + alphaRaw * (4.0 - 3.57);
        const beta = 0.001 + betaRaw * 0.01;
        const gamma = 0.001 + gammaRaw * 0.01;

        // Sinh số vòng warm-up từ hash
        const warmupSeedInt = new DataView(tokenHash).getUint32(tokenHash.byteLength - 4);
        const warmupIterations = 1000 + (warmupSeedInt % 1000);

        // Tạo instance
        const instance = new ChaoticCipher(alpha, beta, gamma, x0, y0, z0, warmupIterations);

        // Tạo keystream key và auth key
        const keystreamKeyPrefix = new TextEncoder().encode('keystream|');
        const authKeyPrefix = new TextEncoder().encode('auth|');
        
        // Nối mảng bằng cách tạo mảng mới
        const keystreamKeyData = new Uint8Array(keystreamKeyPrefix.length + tokenBytes.length);
        keystreamKeyData.set(keystreamKeyPrefix);
        keystreamKeyData.set(tokenBytes, keystreamKeyPrefix.length);

        const authKeyData = new Uint8Array(authKeyPrefix.length + tokenBytes.length);
        authKeyData.set(authKeyPrefix);
        authKeyData.set(tokenBytes, authKeyPrefix.length);
        
        instance._keystreamKey = await crypto.subtle.digest('SHA-256', keystreamKeyData);
        instance._authKey = await crypto.subtle.digest('SHA-256', authKeyData);

        return instance;
    }

    _logisticMap3DInt() {
        // Đồng bộ với Python: sử dụng cùng công thức và phép tính
        const ONE_INT = BigInt(INT_SCALE);

        // Chuyển đổi sang BigInt để tính toán chính xác
        const x_int = BigInt(this._x_int);
        const y_int = BigInt(this._y_int);
        const z_int = BigInt(this._z_int);
        const alpha_int = BigInt(this._alpha_int);
        const beta_int = BigInt(this._beta_int);
        const gamma_int = BigInt(this._gamma_int);

        // Sử dụng phép chia nguyên để đồng bộ với Python
        // x(n+1) = alpha * x * (1-x) + beta * y * z
        const term1_x = (alpha_int * x_int * (ONE_INT - x_int)) / (ONE_INT * ONE_INT);
        const term2_x = (beta_int * y_int * z_int) / ONE_INT;
        const x_new_int = term1_x + term2_x;

        // y(n+1) = alpha * y * (1-y) + beta * x * z
        const term1_y = (alpha_int * y_int * (ONE_INT - y_int)) / (ONE_INT * ONE_INT);
        const term2_y = (beta_int * x_int * z_int) / ONE_INT;
        const y_new_int = term1_y + term2_y;

        // z(n+1) = alpha * z * (1-z) + gamma * x * y
        const term1_z = (alpha_int * z_int * (ONE_INT - z_int)) / (ONE_INT * ONE_INT);
        const term2_z = (gamma_int * x_int * y_int) / ONE_INT;
        const z_new_int = term1_z + term2_z;

        // Chuẩn hóa lại kết quả về khoảng [0, INT_SCALE)
        this._x_int = Number(((x_new_int % ONE_INT) + ONE_INT) % ONE_INT);
        this._y_int = Number(((y_new_int % ONE_INT) + ONE_INT) % ONE_INT);
        this._z_int = Number(((z_new_int % ONE_INT) + ONE_INT) % ONE_INT);

        // Đảm bảo không có giá trị 0
        if (this._x_int === 0) this._x_int = Math.floor(INT_SCALE / 2);
        if (this._y_int === 0) this._y_int = Math.floor(INT_SCALE / 3);
        if (this._z_int === 0) this._z_int = Math.floor(INT_SCALE / 4);
    }

    _generateByteInt() {
        // Sinh một byte từ trạng thái hiện tại
        this._logisticMap3DInt();

        // Lấy 64 bit cuối của mỗi số nguyên lớn
        const mask64Bit = BigInt(2) ** BigInt(64) - BigInt(1);
        const x64 = BigInt(this._x_int) & mask64Bit;
        const y64 = BigInt(this._y_int) & mask64Bit;
        const z64 = BigInt(this._z_int) & mask64Bit;

        // Kết hợp 3 giá trị 64-bit bằng XOR và dịch bit
        // Đồng bộ chính xác với Python
        const combined64 = (x64 ^ (y64 << BigInt(1)) ^ (z64 >> BigInt(1))) & mask64Bit;

        // Lấy 8 bit cuối làm 1 byte keystream
        // Đồng bộ chính xác với Python
        let keystreamByte = Number((combined64 & BigInt(0xFF)) ^ ((combined64 >> BigInt(8)) & BigInt(0xFF))) & 0xFF;
        
        // Đảm bảo không sinh ra số 0
        if (keystreamByte === 0) {
            keystreamByte = 0xFF;
        }

        return keystreamByte;
    }

    warmup(iterations) {
        for (let i = 0; i < iterations; i++) {
            this._logisticMap3DInt();
        }
    }

    generateKeystreamBytes(numBytes) {
        if (!this.isInitialized) {
            console.warn("ChaoticCipher not initialized when calling generateKeystreamBytes");
        }

        const keystream = new Uint8Array(numBytes);
        for (let i = 0; i < numBytes; i++) {
            keystream[i] = this._generateByteInt();
        }
        return keystream;
    }

    async encrypt(data) {
        const keystream = this.generateKeystreamBytes(data.length);
        const result = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
            result[i] = data[i] ^ keystream[i];
        }
        return result;
    }

    async decrypt(encryptedData) {
        // Giải mã giống với mã hóa vì XOR có tính đối xứng
        return this.encrypt(encryptedData);
    }

    async encryptWithHash(data) {
        // Tính hash SHA256 của dữ liệu
        const dataHash = await crypto.subtle.digest('SHA-256', data);

        // Mã hóa dữ liệu + hash gốc
        const payload = new Uint8Array(data.length + 32);
        payload.set(data);
        payload.set(new Uint8Array(dataHash), data.length);

        const encrypted = await this.encrypt(payload);

        // Tính HMAC
        const key = await crypto.subtle.importKey(
            'raw',
            this._authKey,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        const tag = await crypto.subtle.sign('HMAC', key, encrypted);

        // Kết hợp encrypted + tag
        const result = new Uint8Array(encrypted.length + 32);
        result.set(encrypted);
        result.set(new Uint8Array(tag), encrypted.length);

        return result;
    }

    async decryptWithHash(encryptedData) {
        if (encryptedData.length < 64) { // 32 bytes cho hash + 32 bytes cho tag
            throw new Error("Dữ liệu không hợp lệ hoặc thiếu tag.");
        }

        if (!this._authKey) {
            throw new Error("⚠️ Chưa có khóa xác thực!");
        }

        // Tách dữ liệu
        const tag = encryptedData.slice(-32);
        const ciphertext = encryptedData.slice(0, -32);

        // Kiểm tra HMAC
        const key = await crypto.subtle.importKey(
            'raw',
            this._authKey,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['verify']
        );
        const isValid = await crypto.subtle.verify('HMAC', key, tag, ciphertext);
        
        if (!isValid) {
            console.error("‼️ HMAC mismatch!");
            throw new Error("❌ Dữ liệu bị thay đổi hoặc tag không hợp lệ (HMAC sai)");
        }

        // Giải mã
        const decrypted = await this.decrypt(ciphertext);

        // Tách phần gốc và hash
        const data = decrypted.slice(0, -32);
        const dataHash = decrypted.slice(-32);

        // Kiểm tra hash toàn vẹn
        const actualHash = await crypto.subtle.digest('SHA-256', data);
        const actualHashArray = new Uint8Array(actualHash);

        // So sánh hash
        let hashMatch = true;
        for (let i = 0; i < 32; i++) {
            if (actualHashArray[i] !== dataHash[i]) {
                hashMatch = false;
                break;
            }
        }

        if (!hashMatch) {
            console.error("‼️ Hash mismatch!");
            throw new Error("❌ Dữ liệu bị thay đổi hoặc hash sai!");
        }

        return data;
    }

    async resetStateFromToken(token) {
        const newCipher = await ChaoticCipher.instanceFromToken(token);
        this._x_int = newCipher._x_int;
        this._y_int = newCipher._y_int;
        this._z_int = newCipher._z_int;
        this._alpha_int = newCipher._alpha_int;
        this._beta_int = newCipher._beta_int;
        this._gamma_int = newCipher._gamma_int;
        this._keystreamKey = newCipher._keystreamKey;
        this._authKey = newCipher._authKey;
        this.isInitialized = true;
    }

    saveState() {
        return [this._x_int, this._y_int, this._z_int];
    }

    loadState(state) {
        [this._x_int, this._y_int, this._z_int] = state;
    }
}

export default ChaoticCipher;

// Cần đảm bảo backend (Python) sử dụng cùng INT_SCALE và logic tính toán tương tự, lý tưởng là dùng số nguyên lớn tùy ý. 