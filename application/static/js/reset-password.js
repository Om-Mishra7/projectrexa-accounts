function resetPassword() {

    let resetButton = document.getElementById('reset-password-button');
    resetButton.disabled = true;
    resetButton.innerHTML = 'Processing...';

    let newPassword = document.getElementById('password-input-main').value;
    let confirmPassword = document.getElementById('confirm-password-input-main').value;
    let passwordResetToken = document.getElementById('password-reset-token').value;

    if (newPassword !== confirmPassword) {
        createAlert('The two passwords do not match, please try again.', 'danger');
        resetButton.disabled = false;
        resetButton.innerHTML = 'Reset Password';
        return;
    }

    let data = {
        newPassword: newPassword,
        passwordResetToken: passwordResetToken
    };

    fetch('/api/v1/auth/password/reset-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-ProjectRexa-CSRFToken': csrfToken()
        },
        body: JSON.stringify(data)
    }).then(response => {
        return response.json();
    }
    ).then(data => {
        if (data.status === 'success') {
            createAlert('Account password changed successfully, logging you in...', 'success');
            setTimeout(() => {
                window.location.href = '/';
            }, 3000);
        } else {
            createAlert(data.message, 'danger');
            resetButton.disabled = false;
            resetButton.innerHTML = 'Reset Password';
        }
    }).catch(error => {
        createAlert('Our internal systems are facing some issues. Please try again later.', 'danger');
        resetButton.disabled = false;
        resetButton.innerHTML = 'Reset Password';
    });
}