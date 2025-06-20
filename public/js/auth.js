document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const loginTab = document.getElementById('login-tab');
    const signupTab = document.getElementById('signup-tab');
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const roleButtons = document.querySelectorAll('.role-btn');
    const roleInput = document.getElementById('user-role');
    const otpModal = document.getElementById('otp-modal');
    const verifyOtpBtn = document.getElementById('verify-otp');
    const resendOtpBtn = document.getElementById('resend-otp');
    const closeModalBtn = document.querySelector('.close-modal');

    // Tab switching
    function switchTab(activeTab, inactiveTab, activeForm, inactiveForm) {
        activeTab.classList.add('active');
        inactiveTab.classList.remove('active');
        activeForm.classList.add('active');
        inactiveForm.classList.remove('active');
    }

    loginTab.addEventListener('click', (e) => {
        e.preventDefault();
        switchTab(loginTab, signupTab, loginForm, signupForm);
    });

    signupTab.addEventListener('click', (e) => {
        e.preventDefault();
        switchTab(signupTab, loginTab, signupForm, loginForm);
    });

    // Role selection
    roleButtons.forEach(button => {
        button.addEventListener('click', () => {
            roleButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            roleInput.value = button.dataset.role;
        });
    });

    // Password toggle
    document.querySelectorAll('.toggle-password').forEach(toggle => {
        toggle.addEventListener('click', function() {
            const input = this.previousElementSibling;
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);
            this.classList.toggle('fa-eye-slash');
        });
    });

    // OTP digit input handling
    const otpDigits = document.querySelectorAll('.otp-digit');
    otpDigits.forEach((digit, index) => {
        digit.addEventListener('input', (e) => {
            if (e.target.value.length === 1 && index < otpDigits.length - 1) {
                otpDigits[index + 1].focus();
            }
        });

        digit.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && e.target.value.length === 0 && index > 0) {
                otpDigits[index - 1].focus();
            }
        });
    });

    // Close modal
    closeModalBtn.addEventListener('click', () => {
        otpModal.style.display = 'none';
    });

    // Signup form submission
    signupForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const formData = {
            name: document.getElementById('signup-name').value.trim(),
            email: document.getElementById('signup-email').value.trim(),
            phone: document.getElementById('signup-phone').value.trim(),
            password: document.getElementById('signup-password').value,
            confirmPassword: document.getElementById('signup-confirm-password').value,
            role: roleInput.value
        };

        // Client-side validation
        if (!formData.email.includes('@') || !formData.email.includes('.')) {
            alert('Please enter a valid email address');
            return;
        }

        if (formData.password !== formData.confirmPassword) {
            alert('Passwords do not match');
            return;
        }

        if (formData.password.length < 8) {
            alert('Password must be at least 8 characters');
            return;
        }

        // Show loading state
        const submitBtn = e.target.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Sending OTP...';

        try {
            // Send OTP
            const response = await fetch('/send-otp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email: formData.email })
            });

            const data = await response.json();

            if (!data.success) {
                throw new Error(data.message || 'Failed to send OTP');
            }

            // Show OTP modal
            document.getElementById('user-email').textContent = formData.email;
            otpModal.style.display = 'flex';

        } catch (error) {
            console.error('Error:', error);
            alert(error.message || 'An error occurred');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Sign Up';
        }
    });

    // Verify OTP
    verifyOtpBtn.addEventListener('click', async function() {
        const otp = Array.from(document.querySelectorAll('.otp-digit'))
            .map(d => d.value)
            .join('');

        if (otp.length !== 6) {
            alert('Please enter a complete 6-digit OTP');
            return;
        }

        const email = document.getElementById('user-email').textContent;

        // Show loading state
        verifyOtpBtn.disabled = true;
        verifyOtpBtn.textContent = 'Verifying...';

        try {
            // Verify OTP
            const verifyResponse = await fetch('/verify-otp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, otp })
            });

            const verifyData = await verifyResponse.json();

            if (!verifyData.success) {
                throw new Error(verifyData.message || 'OTP verification failed');
            }

            // Complete registration
            const signupResponse = await fetch('/signup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: document.getElementById('signup-name').value.trim(),
                    email,
                    phone: document.getElementById('signup-phone').value.trim(),
                    password: document.getElementById('signup-password').value,
                    confirmPassword: document.getElementById('signup-confirm-password').value,
                    role: roleInput.value
                })
            });

            const signupData = await signupResponse.json();

            if (!signupData.success) {
                throw new Error(signupData.message || 'Registration failed');
            }

            // Success
            otpModal.style.display = 'none';
            alert('Registration successful! Please login.');
            loginTab.click();
            signupForm.reset();

        } catch (error) {
            console.error('Error:', error);
            alert(error.message || 'An error occurred');
        } finally {
            verifyOtpBtn.disabled = false;
            verifyOtpBtn.textContent = 'Verify';
        }
    });

    // Resend OTP
    resendOtpBtn.addEventListener('click', async function(e) {
        e.preventDefault();
        
        const email = document.getElementById('user-email').textContent;
        
        // Show loading state
        resendOtpBtn.textContent = 'Sending...';

        try {
            const response = await fetch('/send-otp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email })
            });

            const data = await response.json();

            if (!data.success) {
                throw new Error(data.message || 'Failed to resend OTP');
            }

            alert('New OTP sent successfully');

        } catch (error) {
            console.error('Error:', error);
            alert(error.message || 'An error occurred');
        } finally {
            resendOtpBtn.textContent = 'Resend';
        }
    });

    // Login form submission
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const email = document.getElementById('login-email').value.trim();
        const password = document.getElementById('login-password').value;

        // Show loading state
        const submitBtn = e.target.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Logging in...';

        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (!data.success) {
                throw new Error(data.message || 'Login failed');
            }

            // Redirect based on role
            window.location.href = data.user.role === 'technician' 
                ? 'technician-dashboard.html' 
                : 'https://anjha1.github.io/TechSeva//TechSeva-website/';

        } catch (error) {
            console.error('Error:', error);
            alert(error.message || 'An error occurred during login');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Login';
        }
    });
});
