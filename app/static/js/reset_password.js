function submitForm() {
    grecaptcha.ready(function () {
        const resetPassword = document.getElementById("reset-password-button");
        resetPassword.disabled = true;
        resetPassword.innerHTML = "Resetting...";
        password = document.getElementById("password").value;

        if (password === "") {
            const errorText = document.getElementById("error-text");
            errorText.innerHTML = "Password is missing";
            resetPassword.disabled = false;
            resetPassword.innerHTML = "Reset Password";
            return;
        } 
        grecaptcha
            .execute("6LdINlonAAAAAK5yArQKUqdHU7sIM8lWD_t_ttOU", { action: "submit" })
            .then(function (token) {
                fetch("/reset-password", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        password: document.getElementById("password").value,
                        token: document.getElementById("token").value,
                        recaptcha_response: token,
                    }),
                }).then(function (response) {
                    if (response.status === 200) {
                        window.location.href = "/sign-in";
                    } else {
                        response.json().then(function (data) {
                            const errorText = document.getElementById("error-text");
                            errorText.innerHTML = data.message;
                            resetPassword.disabled = false;
                            resetPassword.innerHTML = "Reset Password";
                        });
                    }
                });
            });
    });
}

