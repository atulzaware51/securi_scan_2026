document.addEventListener('DOMContentLoaded', () => {
    
    // Check which page the user is currently on by looking for the forms
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    // --- LOGIN LOGIC ---
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            // INTERVIEW POINT: preventDefault() stops the browser from refreshing the page, allowing fetch() to work asynchronously.
            e.preventDefault(); 
            
            const btn = document.getElementById('loginBtn');
            const alertBox = document.getElementById('authAlert');
            
            btn.innerText = "Authenticating...";
            btn.disabled = true;

            const payload = new FormData();
            payload.append('username', document.getElementById('loginUser').value);
            payload.append('password', document.getElementById('loginPass').value);

            try {
                // Call the decoupled backend authentication API
                const req = await fetch('../backend/api_login.php', { method: 'POST', body: payload });
                const res = await req.json();

                if (res.status === 'success') {
                    alertBox.classList.replace('d-none', 'd-block');
                    alertBox.className = "alert alert-success small text-center";
                    alertBox.innerText = "Authentication successful. Routing...";
                    
                    // INTERVIEW POINT: Role-Based Routing executed by the client
                    if (res.role === 'admin') {
                        window.location.href = 'admin.html';
                    } else {
                        window.location.href = 'dashboard.html';
                    }
                } else {
                    // Display error gracefully without page reload
                    alertBox.classList.remove('d-none');
                    alertBox.className = "alert alert-danger small text-center";
                    alertBox.innerText = res.message;
                    btn.innerText = "Log In";
                    btn.disabled = false;
                }
            } catch (error) {
                console.error("[AUTH_FAULT]", error);
                alertBox.classList.remove('d-none');
                alertBox.className = "alert alert-danger small text-center";
                alertBox.innerText = "Critical server fault. API connection refused.";
                btn.innerText = "Log In";
                btn.disabled = false;
            }
        });
    }

    // --- REGISTRATION LOGIC ---
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const btn = document.getElementById('registerBtn');
            const alertBox = document.getElementById('authAlert');
            
            btn.innerText = "Provisioning Account...";
            btn.disabled = true;

            const payload = new FormData();
            payload.append('username', document.getElementById('regUser').value);
            payload.append('email', document.getElementById('regEmail').value);
            payload.append('password', document.getElementById('regPass').value);

            try {
                const req = await fetch('../backend/api_register.php', { method: 'POST', body: payload });
                const res = await req.json();

                if (res.status === 'success') {
                    alertBox.classList.remove('d-none');
                    alertBox.className = "alert alert-success small text-center";
                    alertBox.innerText = "Account created safely! Redirecting to login...";
                    
                    // Route to login page after successful registration
                    setTimeout(() => {
                        window.location.href = 'login.html';
                    }, 2000);
                } else {
                    alertBox.classList.remove('d-none');
                    alertBox.className = "alert alert-danger small text-center";
                    alertBox.innerText = res.message;
                    btn.innerText = "Sign Up";
                    btn.disabled = false;
                }
            } catch (error) {
                console.error("[REGISTRATION_FAULT]", error);
                alertBox.classList.remove('d-none');
                alertBox.className = "alert alert-danger small text-center";
                alertBox.innerText = "Database connection fault during provisioning.";
                btn.innerText = "Sign Up";
                btn.disabled = false;
            }
        });
    }
});