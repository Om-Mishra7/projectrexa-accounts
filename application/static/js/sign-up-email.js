function signUpEmail() {
    let userFullName = document.getElementById('sign-up-name-input').value;
    let userEmail = document.getElementById('sign-up-email-input').value;
    let userPassword = document.getElementById('sign-up-password-input').value;
    let missingFields = [];

    if (userFullName === '') {
        missingFields.push('Name');
    }
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
        name: userFullName,
        email: userEmail,
        password: userPassword
    };

    document.getElementById('sign-up-email-button').innerText = 'Signing up...';

    fetch('/api/v1/auth/sign-up/email', {
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
                    window.location.href = `auth/sign-in/identifier/email?brodcast=${data.message}`;
                }, 1000);
            } else {
                createAlert(data.message, 'danger');
                document.getElementById('sign-up-email-button').innerText = 'Sign up';
            }
        })
        .catch(error => {
            createAlert('An error occurred while creating account', 'danger');
            document.getElementById('sign-up-email-button').innerText = 'Sign up';
        });
}
