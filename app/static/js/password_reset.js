function submitForm() {
    grecaptcha.ready(function () {
        const resetPassword = document.getElementById("password-reset-button");
        resetPassword.disabled = true;
        resetPassword.innerHTML = "Sending...";
        email = document.getElementById("email").value;

        if (email === "") {
            const errorText = document.getElementById("error-text");
            errorText.innerHTML = "Email is missing";
            resetPassword.disabled = false;
            resetPassword.innerHTML = "Send Email";
            return;
        } else if (!email.includes("@") || !email.includes(".")) {
            const errorText = document.getElementById("error-text");
            errorText.innerHTML = "Enter a valid email address";
            resetPassword.disabled = false;
            resetPassword.innerHTML = "Send Email";
            return;
        }

        grecaptcha
            .execute("6LdINlonAAAAAK5yArQKUqdHU7sIM8lWD_t_ttOU", { action: "submit" })
            .then(function (token) {
                fetch("/forgot-password", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        email: document.getElementById("email").value,
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
                            resetPassword.innerHTML = "Send Email";
                        });
                    }
                });
            });
    });
}

