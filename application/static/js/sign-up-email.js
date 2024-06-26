function signUpEmail() {

    document.getElementById('sign-up-email-button').disabled = true;
    document.getElementById('sign-up-email-button').innerText = 'Signing up...';

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
        document.getElementById('sign-up-email-button').innerText = 'Sign up';
        document.getElementById('sign-up-email-button').disabled = false;
        return;
    }

    let data = {
        name: userFullName,
        email: userEmail,
        password: userPassword
    };


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
                    window.location.href = `/auth/sign-in?broadcast=${data.message}`;
                }, 1000);
            } else {
                createAlert(data.message, 'danger');
                document.getElementById('sign-up-email-button').innerText = 'Sign up';
                document.getElementById('sign-up-email-button').disabled = false;
            }
        })
        .catch(error => {
            createAlert('Our internal systems are facing some issues. Please try again later.', 'danger');
            document.getElementById('sign-up-email-button').innerText = 'Sign up';
            document.getElementById('sign-up-email-button').disabled = false;
        });
}
