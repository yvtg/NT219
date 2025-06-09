/**
 * Class ChaoticCipher - Xử lý mã hóa/giải mã sử dụng Logistic Map 3D
 * Đảm bảo đồng bộ keystream giữa client và server
 */
class ChaoticCipher {
    constructor() {
        this.alpha = 3.9;
        this.beta = 0.01;
        this.gamma = 0.005;
        this.x = 0.1;
        this.y = 0.2;
        this.z = 0.3;
        this.warmupIterations = 1000;
        this.keyCache = new Map();
        this.positionCache = new Map();
        this.isInitialized = false;
    }

    async init() {
        try {
            // Lấy tham số từ server
            const response = await fetch('/api/keystream-params');
            const data = await response.json();
            
            if (data.status === 'success') {
                const params = data.params;
                this.alpha = params.alpha;
                this.beta = params.beta;
                this.gamma = params.gamma;
                this.x = params.x0;
                this.y = params.y0;
                this.z = params.z0;
                this.warmupIterations = params.warmup_iterations;
                
                // Thực hiện warmup
                this.warmup();
                this.isInitialized = true;
                return true;
            } else {
                throw new Error(data.message || 'Không thể lấy tham số keystream');
            }
        } catch (error) {
            console.error('Lỗi khởi tạo ChaoticCipher:', error);
            return false;
        }
    }

    warmup() {
        for (let i = 0; i < this.warmupIterations; i++) {
            this.logisticMap3D();
        }
    }

    logisticMap3D() {
        const x_new = this.alpha * this.x * (1 - this.x) + this.beta * this.y * this.z;
        const y_new = this.alpha * this.y * (1 - this.y) + this.beta * this.x * this.z;
        const z_new = this.alpha * this.z * (1 - this.z) + this.gamma * this.x * this.y;

        this.x = x_new;
        this.y = y_new;
        this.z = z_new;

        return [x_new, y_new, z_new];
    }

    generateKey(length, frameId) {
        if (!this.isInitialized) {
            throw new Error('ChaoticCipher chưa được khởi tạo');
        }

        // Kiểm tra cache
        if (this.keyCache.has(frameId)) {
            return this.keyCache.get(frameId);
        }

        const key = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            const [x, y, z] = this.logisticMap3D();
            // Kết hợp 3 giá trị để tạo byte
            key[i] = ((x * 255) & 0xFF) ^ 
                    ((y * 255) & 0xFF) ^ 
                    ((z * 255) & 0xFF);
        }

        // Lưu vào cache
        this.keyCache.set(frameId, key);
        return key;
    }

    encryptFrame(frameData, frameId) {
        const key = this.generateKey(frameData.length, frameId);
        const result = new Uint8Array(frameData.length);
        
        // XOR từng byte
        for (let i = 0; i < frameData.length; i++) {
            result[i] = frameData[i] ^ key[i];
        }
        
        return result;
    }

    decryptFrame(frameData, frameId) {
        // Sử dụng cùng key để giải mã
        return this.encryptFrame(frameData, frameId);
    }

    reset() {
        // Reset trạng thái cipher và xóa cache
        this.x = 0.1;
        this.y = 0.2;
        this.z = 0.3;
        this.keyCache.clear();
        this.positionCache.clear();
        this.isInitialized = false;
    }
}

// Export class
window.ChaoticCipher = ChaoticCipher; 