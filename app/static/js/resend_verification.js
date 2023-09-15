function submitForm() {
    grecaptcha.ready(function () {
        const resendButton = document.getElementById("resend-verification-button");
        resendButton.disabled = true;
        resendButton.innerHTML = "Resending...";
        email = document.getElementById("email").value;

        if (email === "") {
            const errorText = document.getElementById("error-text");
            errorText.innerHTML = "Email is missing";
            resendButton.disabled = false;
            resendButton.innerHTML = "Resend verification email";
            return;
        } else if (!email.includes("@") || !email.includes(".")) {
            const errorText = document.getElementById("error-text");
            errorText.innerHTML = "Enter a valid email address";
            resendButton.disabled = false;
            resendButton.innerHTML = "Resend verification email";
            return;
        }

        grecaptcha
            .execute("6LdINlonAAAAAK5yArQKUqdHU7sIM8lWD_t_ttOU", { action: "submit" })
            .then(function (token) {
                fetch("/resend-verification", {
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
                            resendButton.disabled = false;
                            resendButton.innerHTML = "Resend verification email";
                        });
                    }
                });
            });
    });
}

