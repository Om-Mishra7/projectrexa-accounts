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


    const data = {
        password,
        token
    };

    fetch('/api/v1/auth/reset-password', {
        method: 'PUT',
        body: JSON.stringify(data),
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then((response) => {
            if (response.status == 500) {
                createAlert('There was an error while trying to reset your password, please try again later', 'danger');
            }
            else {
                response.json().then((data) => {
                    if (data.status === 'success') {
                        window.location.replace(`/login?alert=${data.message}`);
                    }
                });
            }
        })
        .catch((error) => {
            createAlert('There was an error while trying to reset your password, please try again later', 'danger');
        });
}