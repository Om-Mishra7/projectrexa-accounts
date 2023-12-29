function handleEmailSignIn(event) {
    event.preventDefault();
    var email = document.getElementById('email').value;
    var password = document.getElementById('password').value;

    if (email == '' || password == '') {
        createAlert('Email or password field is empty, fill them up and try again', 'danger');
        return;
    }

    submitBtn = document.getElementById('submit');
    submitBtn.setAttribute('disabled', 'disabled');
    submitBtn.setAttribute('value', 'Signing in...');
    generateReCaptcha('sign_in')
        .then(function (reCaptchaResponse) {
    
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

function handleResetPassword() {
    let email = document.getElementById('email').value;

    if (email == '') {
        createAlert('The email field is empty, fill it up and try again', 'danger');
        return;
    }

    submitBtn = document.getElementById('submit');
    submitBtn.setAttribute('disabled', 'disabled');
    generateReCaptcha('reset_password')
        .then(function (reCaptchaResponse) {
            // The fetch request
            return fetch('/api/v1/forgot-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    'email': email,
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
                createAlert(data.message, 'success');
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


document.onreadystatechange = function () {
    if (document.readyState === 'interactive') {
        let emailInput = document.getElementById('email');

        if (emailInput) {
            let email = new URLSearchParams(window.location.search).get('email');

            if (email !== null) {
                emailInput.value = email;
            }
        }
    }
}
