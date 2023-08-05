function submitForm() {
  grecaptcha.ready(function () {
    const loginButton = document.getElementById("login-button");
    loginButton.disabled = true;
    loginButton.innerHTML = "Logging in...";
    email = document.getElementById("email").value;
    password = document.getElementById("password").value;

    if (email === "" || password === "") {
      const errorText = document.getElementById("error-text");
      errorText.innerHTML = "Email / Password is missing"
      loginButton.disabled = false;
      loginButton.innerHTML = "Log in";
      return;
    }

    else if (!email.includes("@") || !email.includes(".")) {
      const errorText = document.getElementById("error-text");
      errorText.innerHTML = "Enter a valid email address"
      loginButton.disabled = false;
      loginButton.innerHTML = "Log in";
      return;
    }

    grecaptcha
      .execute("6LdINlonAAAAAK5yArQKUqdHU7sIM8lWD_t_ttOU", { action: "submit" })
      .then(function (token) {
        fetch("/sign-in", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: document.getElementById("email").value,
            password: document.getElementById("password").value,
            recaptcha_response: token,
          }),
        }).then(function (response) {
          if (response.status === 200) {
            window.location.href = "/dashboard";
          } else {
            response.json().then(function (data) {
                const errorText = document.getElementById("error-text");
                errorText.innerHTML = data.message;
                loginButton.disabled = false;
                loginButton.innerHTML = "Log in";
            });
          }
        });
      });
  });
}
