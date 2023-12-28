function handleEmailSignIn(event) {
    event.preventDefault();
    var email = document.getElementById('email').value;
    var password = document.getElementById('password').value;

    if (email == '' || password == '') {
        createAlert('Email/Password fields cannot be empty', 'danger');
        return;
    }

    submitBtn = document.getElementById('submit');
    submitBtn.setAttribute('disabled', 'disabled');
    submitBtn.setAttribute('value', 'Signing in...');
    generateReCaptcha('sign_in')
        .then(function (reCaptchaResponse) {
            // The fetch request
            return fetch('/api/v1/sign-in', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    'email': email,
                    'password': password,
                    'reCaptchaResponse': reCaptchaResponse
                })
            });
        })
        .then(function (response) {
            if (response.status === 500) {
                createAlert("Our internal services are facing some issues, you can check the status at https://status.projectrexa.dedyn.io", 'danger');
            }
            return response.json();
        })
        .then(function (data) {
            // Handle success
            if (data.status === 'success') {
                window.location.href = data.redirect;
            } else {
                createAlert(data.message, 'danger');
                submitBtn.removeAttribute('disabled');
                submitBtn.setAttribute('value', 'Sign in');
            }
        })
        .catch(function (error) {
            createAlert(error.message || 'An error occurred, please refresh the page and try again.', 'danger');
        })
        .finally(function () {
            submitBtn.removeAttribute('disabled');
            submitBtn.setAttribute('value', 'Sign in');
        });

}