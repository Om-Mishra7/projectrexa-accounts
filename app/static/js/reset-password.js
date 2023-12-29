function handleResetPassword(event) {
    event.preventDefault();

    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    const token = new URLSearchParams(window.location.search).get('token');

    if (password !== confirmPassword) {
        createAlert('The passwords do not match, please make sure you typed them correctly', 'danger');
        return;
    }


    if (token === null) {
        window.location.replace(`/login?alert=${encodeURIComponent('The password reset link was invalid please make sure you copied the link correctly')}`);
        return;
    }


    generateReCaptcha('reset_password')
        .then((reCaptchaResponse) => {

            return fetch('/api/v1/reset-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    'token': token,
                    'password': password,
                    'reCaptchaResponse': reCaptchaResponse
                })
            })
        }
        )
        .then((response) => {
            if (response.status === 500) {
                createAlert("Our internal services are facing some issues, you can check the status at https://status.projectrexa.dedyn.io", 'danger');
            }
            return response.json();
        })
        .then((data) => {
            if (data.status === 'success') {
                window.location.replace(`/sign-in?alert=${encodeURIComponent(data.message)}`);
            } else {
                createAlert(data.message, 'danger');
            }
        })
        .catch((error) => {
            createAlert(error.message || 'An error occurred, please refresh the page and try again.', 'danger');
        });
}
