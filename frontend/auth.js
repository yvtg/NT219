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
    
    // Form submissions
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginError.textContent = '';

        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const totp_code = document.getElementById('totp_code').value;
        const loginButton = loginForm.querySelector('.btn-login');
        let recaptcha_response = '';
        
        if (recaptchaDiv.style.display === 'block') {
            recaptcha_response = grecaptcha.getResponse();
        }

        if (!email || !password) {
            loginError.textContent = 'Vui lòng điền đầy đủ thông tin!';
            return;
        }

        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailPattern.test(email)) {
            loginError.textContent = 'Email không hợp lệ!';
            return;
        }

        loginButton.disabled = true;
        loginButton.textContent = 'Đang xử lý...';

        try {
            // First, get a CSRF token
            const csrfResponse = await fetch('http://127.0.0.1:8000/api/auth/get-csrf-token', {
                method: 'GET',
                credentials: 'include'
            });
            
            if (!csrfResponse.ok) {
                throw new Error('Failed to get CSRF token');
            }

            // Get the CSRF token from cookies
            const csrfToken = getCookie('csrf_token');
            console.log('Got CSRF token:', csrfToken);

            // Now make the login request with the CSRF token
            const response = await fetch('http://127.0.0.1:8000/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    email,
                    password,
                    totp_code,
                    recaptcha_response
                }),
                credentials: 'include'
            });

            const data = await response.json();
            console.log('Login response:', data);

            if (!response.ok) {
                throw new Error(data.message || 'Login failed');
            }

            // Store tokens
            localStorage.setItem('access_token', data.access_token);
            localStorage.setItem('refresh_token', data.refresh_token);
            if (data.csrf_token) {
                localStorage.setItem('csrf_token', data.csrf_token);
            }

            // Store user role if provided
            if (data.role) {
                localStorage.setItem('userRole', data.role);
            }

            console.log('Login successful, redirecting to main page...');
            window.location.href = './main.html';

        } catch (error) {
            console.error('Login error:', error);
            loginError.textContent = error.message || 'Login failed. Please try again.';
            
            if (error.response?.status === 429 || (error.message || '').includes('CAPTCHA')) {
                recaptchaDiv.style.display = 'block';
            }
        } finally {
            loginButton.disabled = false;
            loginButton.textContent = 'Đăng nhập';
            if (recaptchaDiv.style.display === 'block') {
                grecaptcha.reset();
            }
        }
    });
    
    signupForm.addEventListener('submit', handleSignup);
    magicForm.addEventListener('submit', handleMagicLink);
    
    // Functions
    
    /**
     * Switch between tabs (login, signup, magic link)
     */
    function switchTab(tab) {
        // Reset all tabs and forms
        [loginTab, signupTab, magicTab].forEach(t => t.classList.remove('active'));
        [loginForm, signupForm, magicForm].forEach(f => f.classList.remove('active'));
        
        // Reset error messages
        loginError.textContent = '';
        signupError.textContent = '';
        magicError.textContent = '';
        magicSuccess.textContent = '';
        
        // Hide special elements
        totpContainer.style.display = 'none';
        recaptchaDiv.style.display = 'none';
        
        // Activate the selected tab
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
    
    /**
     * Toggle password field visibility
     */
    function togglePasswordVisibility(inputId, toggleButton) {
        const passwordInput = document.getElementById(inputId);
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        
        // Change the eye icon (in a real app, you'd use proper icons)
        toggleButton.querySelector('span').textContent = type === 'password' ? '👁️' : '👁️‍🗨️';
    }
    
    /**
     * Fetch CSRF token from the server
     */
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
            
            // Enable all form buttons
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
            
            // Disable all form buttons
            document.querySelectorAll('.btn-login').forEach(btn => {
                btn.disabled = true;
            });
            
            csrfTokenReady = false;
        }
    }
    
    /**
     * Check if CSRF token is valid and refresh if needed
     */
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
    
    /**
     * Refresh CSRF token if needed
     */
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
    
    /**
     * Get cookie by name
     */
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return '';
    }
    
    /**
     * Sanitize input to prevent XSS
     */
    function sanitizeInput(value) {
        if (!value) return value;
        return value.replace(/[<>[\]\\/;`]/g, '');
    }
    
    /**
     * Escape HTML to prevent XSS
     */
    function escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
    
    /**
     * Check if password is strong enough
     */
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
    
    /**
     * Handle signup form submission
     */
    async function handleSignup(e) {
        e.preventDefault();
        signupError.textContent = '';
        
        // Check CSRF token
        if (!(await checkCsrfToken())) return;
        
        // Get form data
        const username = sanitizeInput(document.getElementById('fullname').value);
        const email = sanitizeInput(document.getElementById('signup-email').value);
        const password = document.getElementById('signup-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        const agreeTerms = document.getElementById('terms').checked;
        const signupButton = signupForm.querySelector('.btn-login');
        
        // Validate inputs
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
        
        // Check password strength
        const passwordCheck = isStrongPassword(password, username, email);
        if (!passwordCheck.valid) {
            signupError.textContent = passwordCheck.message;
            return;
        }
        
        if (!agreeTerms) {
            signupError.textContent = 'Vui lòng đồng ý với điều khoản sử dụng!';
            return;
        }
        
        // Validate username format
        const usernamePattern = /^[a-zA-Z0-9_.]{3,50}$/;
        if (!usernamePattern.test(username)) {
            signupError.textContent = 'Tên người dùng chỉ được chứa chữ, số, dấu chấm, dấu gạch dưới, dài 3-50 ký tự!';
            return;
        }
        
        // Disable button and show loading state
        signupButton.disabled = true;
        signupButton.textContent = 'Đang xử lý...';
        
        try {
            // Get current CSRF token
            const csrfToken = getCookie('csrf_token');
            console.log('CSRF Token (Signup):', csrfToken);
            
            if (!csrfToken) {
                signupError.textContent = 'CSRF token không tồn tại. Vui lòng làm mới trang.';
                signupButton.disabled = false;
                signupButton.textContent = 'Đăng ký';
                return;
            }
            
            // Send signup request
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
            
            // Handle successful registration
            alert(data.message || 'Đăng ký thành công, vui lòng kiểm tra email để xác minh');
            switchTab('login');
            
        } catch (error) {
            console.error('Register error:', error);
            signupError.textContent = escapeHTML(error.message || 'Đăng ký thất bại.');
            
            // Handle CSRF token errors
            if (error.message.includes('CSRF token invalid')) {
                signupError.textContent = 'CSRF token không hợp lệ. Đang làm mới...';
                const refreshed = await refreshCsrfToken();
                signupError.textContent += refreshed ? ' Vui lòng thử lại.' : ' Không thể làm mới token.';
            }
            
        } finally {
            // Reset button state
            signupButton.disabled = false;
            signupButton.textContent = 'Đăng ký';
        }
    }
    
    /**
     * Handle magic link form submission
     */
    async function handleMagicLink(e) {
        e.preventDefault();
        magicError.textContent = '';
        magicSuccess.textContent = '';
        
        // Check CSRF token
        if (!(await checkCsrfToken())) return;
        
        // Get form data
        const email = sanitizeInput(document.getElementById('magic-email').value);
        const magicButton = magicForm.querySelector('.btn-login');
        
        // Validate email
        if (!email) {
            magicError.textContent = 'Vui lòng nhập email!';
            return;
        }
        
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailPattern.test(email)) {
            magicError.textContent = 'Email không hợp lệ!';
            return;
        }
        
        // Disable button and show loading state
        magicButton.disabled = true;
        magicButton.textContent = 'Đang xử lý...';
        
        try {
            // Get current CSRF token
            const csrfToken = getCookie('csrf_token');
            console.log('CSRF Token (Magic):', csrfToken);
            
            if (!csrfToken) {
                magicError.textContent = 'CSRF token không tồn tại. Vui lòng làm mới trang.';
                magicButton.disabled = false;
                magicButton.textContent = 'Gửi Magic Link';
                return;
            }
            
            // Send magic link request
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
            
            // Show success message
            magicSuccess.textContent = data.message || 'Magic link đã được gửi!';
            document.getElementById('magic-email').value = '';
            
        } catch (error) {
            console.error('Magic link error:', error);
            magicError.textContent = escapeHTML(error.message || 'Gửi magic link thất bại.');
            
            // Handle CSRF token errors
            if (error.message.includes('CSRF token invalid')) {
                magicError.textContent = 'CSRF token không hợp lệ. Đang làm mới...';
                const refreshed = await refreshCsrfToken();
                magicError.textContent += refreshed ? ' Vui lòng thử lại.' : ' Không thể làm mới token.';
            }
            
        } finally {
            // Reset button state
            magicButton.disabled = false;
            magicButton.textContent = 'Gửi Magic Link';
        }
    }
});

async function checkSessionForLoginPage() {
    const token = localStorage.getItem('access_token');
    if (!token) return;
    
    try {
        const response = await axios.get('http://127.0.0.1:8000/api/auth/check_session', {
            headers: { 
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        
        // Token hợp lệ, chuyển đến trang chính
        console.log('Valid token found, redirecting to main page');
        window.location.href = './main.html';
        
    } catch (error) {
        // Token không hợp lệ, xóa và ở lại trang login
        console.log('Invalid token, clearing and staying on login page');
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('csrf_token');
    }
}

function initializePage() {
    const currentPage = window.location.pathname;
    console.log('Current page:', currentPage);
    
    if (currentPage.includes('index.html') || currentPage === '/' || currentPage.includes('login')) {
        // Trang login - kiểm tra nếu đã đăng nhập thì chuyển hướng
        const token = localStorage.getItem('access_token');
        if (token) {
            console.log('Already logged in, checking session validity...');
            // Kiểm tra token có hợp lệ không trước khi redirect
            checkSessionForLoginPage();
        } else {
            console.log('Not logged in, staying on login page');
        }
    } else {
        // Các trang khác - kiểm tra session
        console.log('Protected page, checking session...');
        checkSession();
    }
}

document.addEventListener('DOMContentLoaded', initializePage);
