function handleEmailSignup(event) {
    event.preventDefault();
    let firstName = document.getElementById('first-name').value;
    let lastName = document.getElementById('last-name').value;
    let email = document.getElementById('email').value;
    let password = document.getElementById('password').value;

    if (email == '' || password == '' || firstName == '' || lastName == '') {
        createAlert('Make sure all fields are filled before submitting.', 'danger');
        return;
    }

    submitBtn = document.getElementById('submit');
    submitBtn.setAttribute('disabled', 'disabled');
    submitBtn.setAttribute('value', 'Signing up...');
    generateReCaptcha('sign_up')
        .then(function (reCaptchaResponse) {
            return fetch('/api/v1/sign-up', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    'firstName': firstName,
                    'lastName': lastName,
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
                window.location.href = `${data.redirect}?email=${email}`;
            } else {
                createAlert(data.message, 'danger');
                submitBtn.removeAttribute('disabled');
                submitBtn.setAttribute('value', 'Sign up');
            }
        })
        .catch(function (error) {
            createAlert(error.message || 'An error occurred, please refresh the page and try again.', 'danger');
        })
        .finally(function () {
            submitBtn.removeAttribute('disabled');
            submitBtn.setAttribute('value', 'Sign up');
        });

}