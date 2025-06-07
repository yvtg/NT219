document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const loginTab = document.getElementById('login-tab');
    const signupTab = document.getElementById('signup-tab');
    const magicTab = document.getElementById('magic-tab');
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const magicForm = document.getElementById('magic-link-form');
    const switchToSignup = document.getElementById('switch-to-signup');
    const switchToLogin = document.getElementById('switch-to-login');
    const loginError = document.getElementById('login-error');
    const signupError = document.getElementById('signup-error');
    const magicError = document.getElementById('magic-error');
    const magicSuccess = document.getElementById('magic-success');
    const totpContainer = document.getElementById('totp-container');
    const recaptchaDiv = document.getElementById('recaptcha');
    const csrfStatus = document.getElementById('csrf-status');
    const modal2FA = document.getElementById('modal-2fa');
    const closeModal = document.querySelector('.close-modal');
    const verify2FAButton = document.getElementById('verify-2fa');
    const twoFAMessage = document.getElementById('2fa-message');

    // Password toggle elements
    const togglePassword = document.getElementById('toggle-password');
    const toggleSignupPassword = document.getElementById('toggle-signup-password');
    const toggleConfirmPassword = document.getElementById('toggle-confirm-password');

    // CSRF token state
    let csrfToken = null;
    let csrfTokenReady = false;

    // reCAPTCHA variable declaration
    const grecaptcha = window.grecaptcha;

    // Fetch CSRF token on page load
    fetchCsrfToken();

    // Tab switching
    loginTab.addEventListener('click', () => switchTab('login'));
    signupTab.addEventListener('click', () => switchTab('signup'));
    magicTab.addEventListener('click', () => switchTab('magic'));
    switchToSignup.addEventListener('click', (e) => {
        e.preventDefault();
        switchTab('signup');
    });
    switchToLogin.addEventListener('click', (e) => {
        e.preventDefault();
        switchTab('login');
    });

    // Close 2FA modal
    if (closeModal) {
        closeModal.addEventListener('click', () => {
            modal2FA.style.display = 'none';
            twoFAMessage.textContent = '';
        });
    }

    // Password visibility toggle
    togglePassword.addEventListener('click', () => {
        togglePasswordVisibility('password', togglePassword);
    });

    toggleSignupPassword.addEventListener('click', () => {
        togglePasswordVisibility('signup-password', toggleSignupPassword);
    });

    toggleConfirmPassword.addEventListener('click', () => {
        togglePasswordVisibility('confirm-password', toggleConfirmPassword);
    });

let isCaptchaRequired = false;

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginError.textContent = '';

    const email = sanitizeInput(document.getElementById('email').value);
    const password = document.getElementById('password').value;
    const totp_code = document.getElementById('totp_code').value;
    const loginButton = loginForm.querySelector('.btn-login');

    // 1. Kiểm tra các input cơ bản trước
    if (!email || !password) {
        loginError.textContent = 'Vui lòng điền đầy đủ thông tin!';
        return;
    }

    // 2. Kiểm tra CSRF token
    if (!(await checkCsrfToken())) {
        loginError.textContent = 'Lỗi bảo mật (CSRF). Vui lòng tải lại trang.';
        return;
    }

    // 3. Logic xử lý reCAPTCHA (CHỈ KIỂM TRA KHI CẦN THIẾT)
    let recaptcha_response = '';
    if (isCaptchaRequired) {
        // Kiểm tra xem grecaptcha đã sẵn sàng chưa
        if (typeof grecaptcha === 'undefined' || !grecaptcha.getResponse) {
            loginError.textContent = 'Lỗi: reCAPTCHA chưa được tải xong. Vui lòng đợi một lát và thử lại.';
            return;
        }
        recaptcha_response = grecaptcha.getResponse();
        // Nếu bắt buộc phải có captcha mà người dùng chưa tick -> dừng lại
        if (!recaptcha_response) {
            loginError.textContent = 'Vui lòng xác thực bạn không phải là người máy.';
            return;
        }
        alert(recaptcha_response);
    }

    // 4. Bắt đầu quá trình gửi request
    loginButton.disabled = true;
    loginButton.textContent = 'Đang xử lý...';

    // 5. Xây dựng payload
    const payload = {
        email,
        password,
        recaptcha_response 
    };
    if (totp_code) {
        payload.totp_code = totp_code;
    }

    try {
        const csrfToken = getCookie('csrf_token');
        if (!csrfToken) throw new Error('CSRF token không tồn tại.');

        const response = await fetch('http://127.0.0.1:8000/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify(payload),
            credentials: 'include'
        });

        const data = await response.json();
        console.log('Login response:', data);

        if (!response.ok) {
            if (data.requires_device_verification === true) {
            // TRƯỜNG HỢP MỚI: THIẾT BỊ CẦN XÁC THỰC
                loginError.textContent = data.message || 'Phát hiện thiết bị mới. Vui lòng kiểm tra email của bạn để xác thực.';

            } else if (data.message?.includes('CAPTCHA')) {
            // Logic cũ của bạn: Xử lý CAPTCHA
                loginError.textContent = 'Quá nhiều lần thử. Vui lòng xác thực CAPTCHA.';
                recaptchaDiv.style.display = 'block';
                isCaptchaRequired = true;
                grecaptcha.reset();

            } else if (data.requires_2fa) {
                // Logic cũ của bạn: Xử lý 2FA
                totpContainer.style.display = 'block';
                loginError.textContent = 'Vui lòng nhập mã 2FA';

            } else {
                // Logic cũ của bạn: Các lỗi khác
                throw new Error(data.message || 'Đăng nhập thất bại');
            }

            // --- KẾT THÚC LOGIC CẦN CẬP NHẬT ---
            return;
        }

        // Đăng nhập thành công
        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('refresh_token', data.refresh_token);
        if (data.csrf_token) localStorage.setItem('csrf_token', data.csrf_token);
        if (data.role) localStorage.setItem('userRole', data.role);

        window.location.href = './main.html';

    } catch (error) {
        console.error('Login error:', error);
        loginError.textContent = escapeHTML(error.message || 'Đăng nhập thất bại. Vui lòng kiểm tra lại thông tin.');
    } finally {
        loginButton.disabled = false;
        loginButton.textContent = 'Đăng nhập';
    }
});

    // Verify 2FA code
    if (verify2FAButton) {
        verify2FAButton.addEventListener('click', async () => {
            const code = sanitizeInput(document.getElementById('verify-2fa-code').value);
            const token = localStorage.getItem('access_token');

            if (!code) {
                twoFAMessage.textContent = 'Vui lòng nhập mã 2FA.';
                return;
            }

            try {
                const response = await fetch('http://127.0.0.1:8000/api/auth/verify-2fa', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': getCookie('csrf_token'),
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ totp_code: code }),
                    credentials: 'include'
                });

                const data = await response.json();
                console.log('2FA verify response:', data);

                if (!response.ok) {
                    throw new Error(data.message || 'Xác minh 2FA thất bại.');
                }

                if (data.success) {
                    modal2FA.style.display = 'none';
                    alert('2FA đã được kích hoạt thành công!');
                }
            } catch (error) {
                console.error('2FA verify error:', error);
                twoFAMessage.textContent = escapeHTML(error.message || 'Mã 2FA không hợp lệ.');
            }
        });
    }

    signupForm.addEventListener('submit', handleSignup);
    magicForm.addEventListener('submit', handleMagicLink);

    // Functions (your existing functions remain unchanged)
    function switchTab(tab) {
        [loginTab, signupTab, magicTab].forEach(t => t.classList.remove('active'));
        [loginForm, signupForm, magicForm].forEach(f => f.classList.remove('active'));
        
        loginError.textContent = '';
        signupError.textContent = '';
        magicError.textContent = '';
        magicSuccess.textContent = '';
        
        totpContainer.style.display = 'none';
        recaptchaDiv.style.display = 'none';
        
        if (tab === 'login') {
            loginTab.classList.add('active');
            loginForm.classList.add('active');
        } else if (tab === 'signup') {
            signupTab.classList.add('active');
            signupForm.classList.add('active');
        } else if (tab === 'magic') {
            magicTab.classList.add('active');
            magicForm.classList.add('active');
        }
    }

    function togglePasswordVisibility(inputId, toggleButton) {
        const passwordInput = document.getElementById(inputId);
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        toggleButton.querySelector('span').textContent = type === 'password' ? '👁️' : '👁️‍🗨️';
    }

    async function fetchCsrfToken() {
        try {
            csrfStatus.innerHTML = '<div style="color: #f5f5f5;">Đang lấy CSRF token...</div>';
            
            const response = await fetch('http://127.0.0.1:8000/api/auth/get-csrf-token', {
                method: 'GET',
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            csrfToken = getCookie('csrf_token');
            
            if (!csrfToken) {
                throw new Error('CSRF token cookie not set');
            }
            
            console.log('CSRF token fetched:', csrfToken);
            csrfTokenReady = true;
            csrfStatus.innerHTML = '<div style="color: #2ecc71;">CSRF token đã sẵn sàng</div>';
            
            document.querySelectorAll('.btn-login').forEach(btn => {
                btn.disabled = false;
            });
        } catch (error) {
            console.error('Failed to fetch CSRF token:', error);
            csrfStatus.innerHTML = `
                <div style="color: #e50914;">
                    Không thể lấy CSRF token. 
                    <button onclick="window.location.reload()" style="background: none; border: none; color: #fff; text-decoration: underline; cursor: pointer;">
                        Làm mới trang
                    </button>
                </div>
            `;
            
            document.querySelectorAll('.btn-login').forEach(btn => {
                btn.disabled = true;
            });
            
            csrfTokenReady = false;
        }
    }

    async function checkCsrfToken() {
        if (!csrfTokenReady) {
            console.log('CSRF token not ready, fetching...');
            await fetchCsrfToken();
        }
        
        if (!csrfToken || !csrfTokenReady) {
            loginError.textContent = 'CSRF token không tồn tại. Vui lòng làm mới trang hoặc thử lại.';
            signupError.textContent = 'CSRF token không tồn tại. Vui lòng làm mới trang hoặc thử lại.';
            magicError.textContent = 'CSRF token không tồn tại. Vui lòng làm mới trang hoặc thử lại.';
            return false;
        }
        
        return true;
    }

    async function refreshCsrfToken() {
        try {
            await fetchCsrfToken();
            console.log('CSRF token refreshed:', getCookie('csrf_token'));
            return true;
        } catch (error) {
            console.error('Failed to refresh CSRF token:', error);
            return false;
        }
    }

    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return '';
    }

    function sanitizeInput(value) {
        if (!value) return value;
        return value.replace(/[<>[\]\\/;`]/g, '');
    }

    function escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function isStrongPassword(password, username, email) {
        if (password.length < 12) 
            return { valid: false, message: 'Mật khẩu phải dài ít nhất 12 ký tự' };
        
        if (!/[A-Z]/.test(password)) 
            return { valid: false, message: 'Mật khẩu phải chứa ít nhất một chữ cái in hoa' };
        
        if (!/[a-z]/.test(password)) 
            return { valid: false, message: 'Mật khẩu phải chứa ít nhất một chữ cái thường' };
        
        if (!/[0-9]/.test(password)) 
            return { valid: false, message: 'Mật khẩu phải chứa ít nhất một số' };
        
        if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) 
            return { valid: false, message: 'Mật khẩu phải chứa ít nhất một ký tự đặc biệt' };
        
        if (
            password.toLowerCase().includes(username.toLowerCase()) ||
            password.toLowerCase().includes(email.toLowerCase())
        ) {
            return { valid: false, message: 'Mật khẩu không được chứa tên người dùng hoặc email' };
        }
        
        const commonPatterns = ['password', '1234', 'qwerty'];
        if (commonPatterns.some(pattern => password.toLowerCase().includes(pattern))) {
            return { valid: false, message: 'Mật khẩu chứa các mẫu phổ biến' };
        }
        
        return { valid: true, message: '' };
    }

    async function handleSignup(e) {
        e.preventDefault();
        signupError.textContent = '';
        
        if (!(await checkCsrfToken())) return;
        
        const username = sanitizeInput(document.getElementById('fullname').value);
        const email = sanitizeInput(document.getElementById('signup-email').value);
        const password = document.getElementById('signup-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        const agreeTerms = document.getElementById('terms').checked;
        const signupButton = signupForm.querySelector('.btn-login');
        
        if (!username || !email || !password || !confirmPassword) {
            signupError.textContent = 'Vui lòng điền đầy đủ thông tin!';
            return;
        }
        
        if (password !== confirmPassword) {
            signupError.textContent = 'Mật khẩu xác nhận không khớp!';
            return;
        }
        
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailPattern.test(email)) {
            signupError.textContent = 'Email không hợp lệ!';
            return;
        }
        
        const passwordCheck = isStrongPassword(password, username, email);
        if (!passwordCheck.valid) {
            signupError.textContent = passwordCheck.message;
            return;
        }
        
        if (!agreeTerms) {
            signupError.textContent = 'Vui lòng đồng ý với điều khoản sử dụng!';
            return;
        }
        
        const usernamePattern = /^[a-zA-Z0-9_.]{3,50}$/;
        if (!usernamePattern.test(username)) {
            signupError.textContent = 'Tên người dùng chỉ được chứa chữ, số, dấu chấm, dấu gạch dưới, dài 3-50 ký tự!';
            return;
        }
        
        signupButton.disabled = true;
        signupButton.textContent = 'Đang xử lý...';
        
        try {
            const csrfToken = getCookie('csrf_token');
            console.log('CSRF Token (Signup):', csrfToken);
            
            if (!csrfToken) {
                signupError.textContent = 'CSRF token không tồn tại. Vui lòng làm mới trang.';
                signupButton.disabled = false;
                signupButton.textContent = 'Đăng ký';
                return;
            }
            
            const response = await fetch('http://127.0.0.1:8000/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    username,
                    email,
                    password
                }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Đăng ký thất bại');
            }
            
            alert(data.message || 'Đăng ký thành công, vui lòng kiểm tra email để xác minh');
            switchTab('login');
            
        } catch (error) {
            console.error('Register error:', error);
            signupError.textContent = escapeHTML(error.message || 'Đăng ký thất bại.');
            
            if (error.message.includes('CSRF token invalid')) {
                signupError.textContent = 'CSRF token không hợp lệ. Đang làm mới...';
                const refreshed = await refreshCsrfToken();
                signupError.textContent += refreshed ? ' Vui lòng thử lại.' : ' Không thể làm mới token.';
            }
            
        } finally {
            signupButton.disabled = false;
            signupButton.textContent = 'Đăng ký';
        }
    }

    async function handleMagicLink(e) {
        e.preventDefault();
        magicError.textContent = '';
        magicSuccess.textContent = '';
        
        if (!(await checkCsrfToken())) return;
        
        const email = sanitizeInput(document.getElementById('magic-email').value);
        const magicButton = magicForm.querySelector('.btn-login');
        
        if (!email) {
            magicError.textContent = 'Vui lòng nhập email!';
            return;
        }
        
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailPattern.test(email)) {
            magicError.textContent = 'Email không hợp lệ!';
            return;
        }
        
        magicButton.disabled = true;
        magicButton.textContent = 'Đang xử lý...';
        
        try {
            const csrfToken = getCookie('csrf_token');
            console.log('CSRF Token (Magic):', csrfToken);
            
            if (!csrfToken) {
                magicError.textContent = 'CSRF token không tồn tại. Vui lòng làm mới trang.';
                magicButton.disabled = false;
                magicButton.textContent = 'Gửi Magic Link';
                return;
            }
            
            const response = await fetch('http://127.0.0.1:8000/api/auth/request-magic-link', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    email
                }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Gửi magic link thất bại');
            }
            
            magicSuccess.textContent = data.message || 'Magic link đã được gửi!';
            document.getElementById('magic-email').value = '';
            
        } catch (error) {
            console.error('Magic link error:', error);
            magicError.textContent = escapeHTML(error.message || 'Gửi magic link thất bại.');
            
            if (error.message.includes('CSRF token invalid')) {
                magicError.textContent = 'CSRF token không hợp lệ. Đang làm mới...';
                const refreshed = await refreshCsrfToken();
                magicError.textContent += refreshed ? ' Vui lòng thử lại.' : ' Không thể làm mới token.';
            }
            
        } finally {
            magicButton.disabled = false;
            magicButton.textContent = 'Gửi Magic Link';
        }
    }
});

async function checkSessionForLoginPage() {
    const token = localStorage.getItem('access_token');
    if (!token) return;

    try {
        const response = await fetch('http://127.0.0.1:8000/api/auth/check_session', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCookie('csrf_token')
            },
            credentials: 'include'
        });

        if (response.ok) {
            console.log('Valid token found, redirecting to main page');
            window.location.href = './main.html';
        } else {
            throw new Error('Invalid token');
        }
    } catch (error) {
        console.log('Invalid token, clearing and staying on login page');
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('csrf_token');
    }
}

async function check2FAStatus() {
    const token = localStorage.getItem('access_token');
    if (!token) return false;

    try {
        const response = await fetch('http://127.0.0.1:8000/api/auth/2fa-status', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCookie('csrf_token'),
                'Authorization': `Bearer ${token}`
            },
            credentials: 'include'
        });

        const data = await response.json();
        return data.is_2fa_enabled || false;
    } catch (error) {
        console.error('Error checking 2FA status:', error);
        return false;
    }
}
async function checkEnable2FA(){
    
}
async function initializePage() {
    const isEnable=await checkEnable2FA();
    if(isEnable){
        document.getElementById('enable-2fa').style.display = 'none';
    }
    const currentPage = window.location.pathname;
    console.log('Current page:', currentPage);

    if (currentPage.includes('index.html') || currentPage === '/' || currentPage.includes('login')) {
        const token = localStorage.getItem('access_token');
        if (token) {
            console.log('Already logged in, checking session validity...');
            checkSessionForLoginPage();
        } else {
            console.log('Not logged in, staying on login page');
        }
    } else {
        console.log('Protected page, checking session...');
        checkSession();
    }
}

document.addEventListener('DOMContentLoaded', initializePage);

// Placeholder for checkSession (for protected pages)
async function checkSession() {
    const token = localStorage.getItem('access_token');
    if (!token) {
        window.location.href = './index.html';
        return;
    }

    try {
        const response = await fetch('http://127.0.0.1:8000/api/auth/check_session', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCookie('csrf_token')
            },
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('Invalid session');
        }
    } catch (error) {
        console.log('Session invalid, redirecting to login');
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('csrf_token');
        window.location.href = './index.html';
    }
}