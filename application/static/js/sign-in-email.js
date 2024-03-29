function signInEmail() {
    let userEmail = document.getElementById('sign-in-email-input').value;
    let userPassword = document.getElementById('sign-in-password-input').value;
    let missingFields = [];

    if (userEmail === '') {
        missingFields.push('Email');
    }
    if (userPassword === '') {
        missingFields.push('Password');
    }

    if (missingFields.length > 0) {
        let missingFieldsMessage = '';
        if (missingFields.length === 1) {
            missingFieldsMessage = missingFields[0];
        } else if (missingFields.length === 2) {
            missingFieldsMessage = missingFields.join(' and ');
        } else {
            missingFieldsMessage = missingFields.slice(0, -1).join(', ') + ' and ' + missingFields.slice(-1);
        }
        createAlert(`It seems you have missed the required fields: ${missingFieldsMessage}.`, 'danger');
        return;
    }

    let data = {
        email: userEmail,
        password: userPassword
    };

    document.getElementById('sign-in-email-button').innerText = 'Signing in...';

    fetch('/api/v1/auth/sign-in/email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-ProjectRexa-CSRFToken': csrfToken()
        },
        body: JSON.stringify(data)
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                setTimeout(() => {
                    let urlParams = new URLSearchParams(window.location.search);
                    let next = urlParams.get('next');
                    if (next) {
                        window.location.href = next;
                    }
                    window.location.href = '/';
                }, 1000);
            } else {
                if (data.message === 'The account is not verified, please verify the email address') {
                    createAlert("The account is not verified, please verify the email address or request a request a <a href='/auth/email/resend-account-verification'>verification email</a>.", 'danger');
                }
                createAlert(data.message, 'danger');
                document.getElementById('sign-in-email-button').innerText = 'Sign in';
            }
        })
        .catch(error => {
            createAlert('Our internal systems are facing some issues. Please try again later.', 'danger');
            document.getElementById('sign-in-email-button').innerText = 'Sign in';
        });
}