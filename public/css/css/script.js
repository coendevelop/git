// Auth
const usernameInput = document.getElementById('username');
const nextBtn = document.getElementById('nextBtn');
const passwordSection = document.getElementById('passwordSection');
const registerFields = document.getElementById('registerFields');
const authForm = document.getElementById('authForm');
const title = document.getElementById('title');

nextBtn.onclick = async () => {
    const user = usernameInput.value;
    if(!user) return;

    const res = await fetch(`/check-user?username=${user}`);
    const data = await res.json();

    passwordSection.classList.remove('hidden');
    nextBtn.classList.add('hidden');

    if (data.exists) {
        title.innerText = "Log In";
        authForm.action = "/login";
    } else {
        title.innerText = "Create Account";
        authForm.action = "/register";
        registerFields.classList.remove('hidden');
        document.getElementById('confirmPassword').required = true;
    }
};
authForm.onsubmit = () => {
    // Disable the button and change text so the user knows it's working
    const btn = document.getElementById('submitBtn');
    btn.disabled = true;
    btn.innerText = "Creating Account...";
};

