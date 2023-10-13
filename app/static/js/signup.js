function submitForm() {
  grecaptcha.ready(function () {
    const loginButton = document.getElementById("signup-button");
    loginButton.disabled = true;
    loginButton.innerHTML = "Signing up...";
    username = document.getElementById("username").value;
    email = document.getElementById("email").value;
    password = document.getElementById("password").value;

    if (email === "" || password === "" || username === "") {
      const errorText = document.getElementById("error-text");
      errorText.innerHTML = "Email / Password / Username is missing";
      loginButton.disabled = false;
      loginButton.innerHTML = "Sign up";
      return;
    } else if (!email.includes("@") || !email.includes(".")) {
      const errorText = document.getElementById("error-text");
      errorText.innerHTML = "Enter a valid email address";
      loginButton.disabled = false;
      loginButton.innerHTML = "Sign up";
      return;
    }

    grecaptcha
      .execute("6LdINlonAAAAAK5yArQKUqdHU7sIM8lWD_t_ttOU", { action: "submit" })
      .then(function (token) {
        fetch("/api/auth/sign-up", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: document.getElementById("email").value,
            password: document.getElementById("password").value,
            username: document.getElementById("username").value,
            recaptcha_response: token,
          }),
        }).then(function (response) {
          if (response.status === 200) {
            window.location.href = "/sign-in";
          } else {
            response.json().then(function (data) {
              const errorText = document.getElementById("error-text");
              errorText.innerHTML = data.message;
              loginButton.disabled = false;
              loginButton.innerHTML = "Sign up";
            });
          }
        });
      });
  });
}
