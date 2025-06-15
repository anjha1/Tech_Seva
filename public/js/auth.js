// Utility for displaying messages (replaces alert/confirm)
const showMessage = (message, type = 'success') => {
    const messageContainer = document.getElementById('message-container');
    if (!messageContainer) return;

    // Remove any existing messages to only show the latest
    const existingMessageBox = messageContainer.querySelector('.message-box');
    if (existingMessageBox) {
        existingMessageBox.remove();
    }

    const messageBox = document.createElement('div');
    messageBox.className = `message-box ${type}`;
    messageBox.textContent = message;
    messageContainer.appendChild(messageBox);

    setTimeout(() => {
        // Fade out and remove the message box
        messageBox.style.opacity = '0';
        setTimeout(() => messageBox.remove(), 500); // Wait for fadeOut animation
    }, 4500); // Message visible for 4.5 seconds before fading out
};

document.addEventListener('DOMContentLoaded', () => {
    // --- General UI Elements ---
    const menuToggle = document.getElementById('menu-toggle');
    const mainNavMenu = document.getElementById('main-nav-menu');
    const loginNavBtn = document.getElementById('login-nav-btn');
    const joinTechBtn = document.getElementById('join-tech-btn'); // Hero section 'Join as Technician'
    const customerCtaBtn = document.getElementById('customer-cta-btn'); // 'I am a Customer' CTA
    const technicianCtaBtn = document.getElementById('technician-cta-btn'); // 'I am a Technician' CTA
    const adminCtaBtn = document.getElementById('admin-cta-btn'); // 'I am an Admin' CTA
    const bookServiceBtn = document.getElementById('book-service-btn'); // Hero section 'Book Service'
    const getDiagnosisBtn = document.getElementById('get-diagnosis-btn'); // AI Diagnosis button
    const applianceProblemInput = document.getElementById('appliance-problem'); // AI Diagnosis textarea
    const diagnosisResultDiv = document.getElementById('diagnosis-result'); // AI Diagnosis result div
    const loadingIndicator = document.getElementById('loading-indicator'); // AI Diagnosis loading indicator

    // --- Auth Modal Elements ---
    const authOverlay = document.getElementById('auth-overlay');
    const closeAuthModal = document.getElementById('close-auth-modal');
    const loginTab = document.getElementById('login-tab');
    const signupTab = document.getElementById('signup-tab');
    const loginForm = document.getElementById('login-form'); // This is the <form> for login
    const signupForm = document.getElementById('signup-form'); // This is the <form> for signup
    const roleButtons = document.querySelectorAll('.role-btn');
    const loginRoleInput = document.getElementById('login-user-role'); // Hidden input in login form
    const signupRoleInput = document.getElementById('signup-user-role'); // Hidden input in signup form
    const technicianFields = document.getElementById('technician-fields'); // Technician specific fields div
    const signupConfirmPasswordGroup = document.getElementById('signup-confirm-password-group'); // Confirm password group for signup

    // --- OTP Modal Elements ---
    const otpModal = document.getElementById('otp-modal');
    const closeOtpModalBtn = otpModal.querySelector('.close-otp-modal');
    const userEmailDisplay = document.getElementById('user-email-display');
    const otpDigits = otpModal.querySelectorAll('.otp-digit');
    const verifyOtpBtn = document.getElementById('verify-otp');
    const resendOtpBtn = document.getElementById('resend-otp');


    // --- Navbar Hamburger Menu Toggle ---
    menuToggle.addEventListener('click', () => {
        mainNavMenu.classList.toggle('active');
    });

    // --- Show Auth Modal Function ---
    const showAuthModal = (initialTab = 'login', initialRole = 'user') => {
        authOverlay.style.display = 'flex'; // Show the modal overlay

        // Set initial tab
        if (initialTab === 'signup') {
            signupTab.click(); // Programmatically click signup tab
        } else {
            loginTab.click(); // Programmatically click login tab
        }

        // Set initial role (simulate click on role button)
        // This is important for setting the correct active style and hidden input value
        roleButtons.forEach(button => {
            if (button.dataset.role === initialRole) {
                button.click(); // This will trigger the role button's click handler
            }
        });
    };

    // --- Event Listeners to Open Auth Modal ---
    loginNavBtn.addEventListener('click', () => showAuthModal('login', 'user'));
    joinTechBtn.addEventListener('click', () => showAuthModal('signup', 'technician'));
    bookServiceBtn.addEventListener('click', (e) => { e.preventDefault(); showAuthModal('login', 'user'); }); // Book service leads to login
    customerCtaBtn.addEventListener('click', (e) => { e.preventDefault(); showAuthModal('login', 'user'); });
    technicianCtaBtn.addEventListener('click', (e) => { e.preventDefault(); showAuthModal('signup', 'technician'); });
    adminCtaBtn.addEventListener('click', (e) => { e.preventDefault(); showAuthModal('login', 'admin'); }); // Admin CTA leads to login

    // --- Close Auth Modal ---
    closeAuthModal.addEventListener('click', () => {
        authOverlay.style.display = 'none';
        showMessage('', null); // Clear any general messages
    });

    // Close auth modal if clicked outside
    authOverlay.addEventListener('click', (e) => {
        if (e.target === authOverlay) {
            authOverlay.style.display = 'none';
            showMessage('', null); // Clear any general messages
        }
    });

    // --- Tab Switching Logic (Login/Signup) ---
    loginTab.addEventListener('click', () => {
        loginTab.classList.add('active');
        signupTab.classList.remove('active');
        loginForm.classList.add('active');
        signupForm.classList.remove('active');

        showMessage('', null); // Clear general message box

        // Ensure technician fields are hidden for login tab
        technicianFields.style.display = 'none';
        // Remove required attributes from technician fields when hidden
        technicianFields.querySelectorAll('input').forEach(input => input.removeAttribute('required'));

        // For login, always default the role to 'user' for the visual selection in the modal
        document.querySelector('.role-btn[data-role="user"]').click(); // Simulate click to set active style and hidden input
    });

    signupTab.addEventListener('click', () => {
        signupTab.classList.add('active');
        loginTab.classList.remove('active');
        signupForm.classList.add('active');
        loginForm.classList.remove('active');

        showMessage('', null); // Clear general message box

        // Default to user on signup tab switch; technician fields visibility will be handled by role click
        document.querySelector('.role-btn[data-role="user"]').click();
    });

    // --- Role Selection Logic (User, Technician, Admin) ---
    roleButtons.forEach(button => {
        button.addEventListener('click', () => {
            roleButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');

            const selectedRole = button.dataset.role;

            // Update hidden role inputs for both forms, depending on which form is active
            if (loginForm.classList.contains('active')) {
                loginRoleInput.value = selectedRole;
            } else if (signupForm.classList.contains('active')) {
                signupRoleInput.value = selectedRole;
                // Toggle technician-specific fields visibility based on role for signup form
                if (selectedRole === 'technician') {
                    technicianFields.style.display = 'block';
                    // Make technician fields required for signup
                    document.getElementById('signup-aadhaar').setAttribute('required', 'required');
                    document.getElementById('signup-pan').setAttribute('required', 'required');
                    document.getElementById('signup-bank').setAttribute('required', 'required');
                    document.getElementById('signup-skills').setAttribute('required', 'required');
                } else {
                    technicianFields.style.display = 'none';
                    // Remove required attribute if not technician
                    document.getElementById('signup-aadhaar').removeAttribute('required');
                    document.getElementById('signup-pan').removeAttribute('required');
                    document.getElementById('signup-bank').removeAttribute('required');
                    document.getElementById('signup-skills').removeAttribute('required');
                }
            }
        });
    });

    // Set initial active role button and hidden input value on page load
    document.querySelector('.role-btn[data-role="user"]').click();


    // --- Password Toggle Logic ---
    document.querySelectorAll('.toggle-password, .toggle-confirm-password').forEach(toggle => {
        toggle.addEventListener('click', () => {
            const passwordInput = toggle.previousElementSibling;
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            toggle.classList.toggle('fa-eye');
            toggle.classList.toggle('fa-eye-slash');
        });
    });

    // --- Login Form Submission ---
    const loginEmailInput = document.getElementById('login-email');
    const loginPasswordInput = document.getElementById('login-password');
    const loginSubmitBtn = loginForm.querySelector('.auth-btn');

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        showMessage('', null); // Clear previous messages

        const email = loginEmailInput.value.trim();
        const password = loginPasswordInput.value;
        const role = loginRoleInput.value;

        if (!email || !password || !role) {
            showMessage('Please enter email, password, and select a role.', 'error');
            return;
        }

        loginSubmitBtn.disabled = true;
        loginSubmitBtn.textContent = 'Logging in...';

        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password, role })
            });
            const result = await response.json();

            if (result.success) {
                showMessage(result.message, 'success');
                if (result.redirect) {
                    setTimeout(() => {
                        window.location.href = result.redirect;
                    }, 500);
                } else {
                    console.warn('Login successful but no redirect URL provided by server. Closing modal.');
                    showMessage('Login successful! Welcome.', 'success');
                    authOverlay.style.display = 'none';
                }
            } else {
                showMessage(result.message, 'error');
                if (result.redirect) {
                    setTimeout(() => {
                        window.location.href = result.redirect;
                    }, 2000);
                }
            }
        } catch (error) {
            console.error('Login error:', error);
            showMessage('Network error during login. Please try again.', 'error');
        } finally {
            loginSubmitBtn.disabled = false;
            loginSubmitBtn.textContent = 'Login';
        }
    });


    // --- Signup Form Submission (Initiates OTP Send) ---
    const signupFullNameInput = document.getElementById('signup-fullname');
    const signupEmailInput = document.getElementById('signup-email');
    const signupPhoneInput = document.getElementById('signup-phone');
    const signupPasswordInput = document.getElementById('signup-password');
    const signupConfirmPasswordInput = document.getElementById('signup-confirm-password');
    const signupAadhaarInput = document.getElementById('signup-aadhaar');
    const signupPanInput = document.getElementById('signup-pan');
    const signupBankInput = document.getElementById('signup-bank');
    const signupSkillsInput = document.getElementById('signup-skills');
    const signupSubmitBtn = signupForm.querySelector('.auth-btn');

    signupForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        showMessage('', null); // Clear previous messages

        const fullName = signupFullNameInput.value.trim();
        const email = signupEmailInput.value.trim();
        const phoneNumber = signupPhoneInput.value.trim();
        const password = signupPasswordInput.value;
        const confirmPassword = signupConfirmPasswordInput.value;
        const role = signupRoleInput.value;

        if (password !== confirmPassword) {
            showMessage('Passwords do not match.', 'error');
            return;
        }
        if (password.length < 8) {
            showMessage('Password must be at least 8 characters.', 'error');
            return;
        }
        if (!email.includes('@') || !email.includes('.')) {
            showMessage('Please enter a valid email address.', 'error');
            return;
        }
        if (!phoneNumber || !/^\d{10}$/.test(phoneNumber)) {
            showMessage('Please enter a valid 10-digit phone number.', 'error');
            return;
        }

        const signupData = { fullName, email, phoneNumber, password, role };
        if (role === 'technician') {
            signupData.aadhaar = signupAadhaarInput.value.trim();
            signupData.pan = signupPanInput.value.trim();
            signupData.bankDetails = signupBankInput.value.trim();
            signupData.skills = signupSkillsInput.value.trim();

            if (!signupData.aadhaar || !signupData.pan || !signupData.bankDetails || !signupData.skills) {
                showMessage('Technician registration requires Aadhaar, PAN, Bank Details, and Skills.', 'error');
                return;
            }
        }

        signupSubmitBtn.disabled = true;
        signupSubmitBtn.textContent = 'Sending OTP...';

        try {
            const otpResponse = await fetch('/send-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: signupData.email })
            });
            const otpResult = await otpResponse.json();

            if (otpResult.success) {
                userEmailDisplay.textContent = signupData.email;
                otpModal.style.display = 'flex';
                showMessage(otpResult.message, 'success');
                sessionStorage.setItem('pendingSignupData', JSON.stringify(signupData));
            } else {
                showMessage(otpResult.message, 'error');
            }
        } catch (error) {
            console.error('Signup (OTP Send) error:', error);
            showMessage('Network error during OTP send. Please try again.', 'error');
        } finally {
            signupSubmitBtn.disabled = false;
            signupSubmitBtn.textContent = 'Sign Up';
        }
    });

    // --- OTP Input focus management ---
    otpDigits.forEach((digitInput, index) => {
        digitInput.addEventListener('input', () => {
            if (digitInput.value.length === 1 && index < otpDigits.length - 1) {
                otpDigits[index + 1].focus();
            }
            const allFilled = Array.from(otpDigits).every(input => input.value.length === 1);
            if (allFilled) {
                verifyOtpBtn.click();
            }
        });

        digitInput.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && digitInput.value === '' && index > 0) {
                otpDigits[index - 1].focus();
            }
        });
    });

    // --- Close OTP Modal ---
    closeOtpModalBtn.addEventListener('click', () => {
        otpModal.style.display = 'none';
        sessionStorage.removeItem('pendingSignupData');
        showMessage('', null);
        otpDigits.forEach(digit => digit.value = '');
    });

    // --- Verify OTP and Complete Registration ---
    verifyOtpBtn.addEventListener('click', async () => {
        showMessage('', null);

        const enteredOtp = Array.from(otpDigits).map(input => input.value).join('');
        const storedSignupData = JSON.parse(sessionStorage.getItem('pendingSignupData'));

        if (!storedSignupData || !storedSignupData.email) {
            showMessage('No pending signup data found. Please restart registration.', 'error');
            otpModal.style.display = 'none';
            return;
        }
        if (enteredOtp.length !== 6) {
            showMessage('Please enter a complete 6-digit OTP.', 'error');
            return;
        }

        verifyOtpBtn.disabled = true;
        verifyOtpBtn.textContent = 'Verifying...';
        resendOtpBtn.disabled = true;

        try {
            const verifyResponse = await fetch('/verify-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: storedSignupData.email, otp: enteredOtp })
            });
            const verifyResult = await verifyResponse.json();

            if (!verifyResult.success) {
                throw new Error(verifyResult.message || 'OTP verification failed.');
            }

            const registerResponse = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(storedSignupData)
            });
            const registerResult = await registerResponse.json();

            if (!registerResult.success) {
                throw new Error(registerResult.message || 'Registration failed after OTP verification.');
            }

            otpModal.style.display = 'none';
            showMessage('Registration successful! You can now login.', 'success');
            loginTab.click();
            signupForm.reset();
            otpDigits.forEach(digit => digit.value = '');
            sessionStorage.removeItem('pendingSignupData');
            authOverlay.style.display = 'none';

        } catch (error) {
            console.error('OTP Verification or Registration Error:', error);
            showMessage(error.message || 'An error occurred during verification or registration.', 'error');
            otpModal.style.display = 'none';
            sessionStorage.removeItem('pendingSignupData');
        } finally {
            verifyOtpBtn.disabled = false;
            verifyOtpBtn.textContent = 'Verify';
            resendOtpBtn.disabled = false;
        }
    });

    // --- Resend OTP ---
    resendOtpBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        showMessage('', null);

        const storedSignupData = JSON.parse(sessionStorage.getItem('pendingSignupData'));

        if (!storedSignupData || !storedSignupData.email) {
            showMessage('No email found to resend OTP. Please restart registration.', 'error');
            return;
        }

        resendOtpBtn.disabled = true;
        resendOtpBtn.textContent = 'Sending...';

        try {
            const response = await fetch('/send-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: storedSignupData.email })
            });
            const result = await response.json();
            if (result.success) {
                showMessage(result.message, 'success');
            } else {
                showMessage(result.message, 'error');
            }
        } catch (error) {
            console.error('Resend OTP error:', error);
            showMessage('Network error while resending OTP.', 'error');
        } finally {
            resendOtpBtn.disabled = false;
            resendOtpBtn.textContent = 'Resend';
        }
    });

    // --- AI Diagnosis Logic ---
    if (getDiagnosisBtn && applianceProblemInput && diagnosisResultDiv && loadingIndicator) {
        getDiagnosisBtn.addEventListener('click', async () => {
            const problemDescription = applianceProblemInput.value.trim();
            diagnosisResultDiv.style.display = 'none';
            diagnosisResultDiv.textContent = '';
            loadingIndicator.style.display = 'none';
            showMessage('', null);

            if (!problemDescription) {
                showMessage('Please describe the problem with your appliance.', 'error');
                return;
            }

            loadingIndicator.style.display = 'block';
            getDiagnosisBtn.disabled = true;
            getDiagnosisBtn.textContent = 'Diagnosing...';

            try {
                let chatHistory = [];
                chatHistory.push({ role: "user", parts: [{ text: `Provide a concise, preliminary diagnosis for an appliance problem. User input: "${problemDescription}". Suggest possible causes and basic troubleshooting steps. Keep it under 200 words.` }] });

                const payload = { contents: chatHistory };
                const apiKey = "";
                const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

                const response = await fetch(apiUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const result = await response.json();
                if (result.candidates && result.candidates.length > 0 &&
                    result.candidates[0].content && result.candidates[0].content.parts &&
                    result.candidates[0].content.parts.length > 0) {
                    const diagnosisText = result.candidates[0].content.parts[0].text;
                    diagnosisResultDiv.textContent = diagnosisText;
                    diagnosisResultDiv.style.display = 'block';
                    showMessage('Diagnosis complete!', 'success');
                } else {
                    diagnosisResultDiv.textContent = 'Could not get a diagnosis. Please try again or rephrase.';
                    diagnosisResultDiv.style.display = 'block';
                    showMessage('Failed to get AI diagnosis.', 'error');
                }
            } catch (error) {
                console.error('AI Diagnosis API error:', error);
                diagnosisResultDiv.textContent = 'An error occurred during diagnosis. Please try again later.';
                diagnosisResultDiv.style.display = 'block';
                showMessage('Error connecting to AI diagnosis service.', 'error');
            } finally {
                loadingIndicator.style.display = 'none';
                getDiagnosisBtn.disabled = false;
                getDiagnosisBtn.textContent = 'Get AI Diagnosis ✨';
            }
        });
    }
});
