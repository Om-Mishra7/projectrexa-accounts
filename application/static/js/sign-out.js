function signOut() {
    document.getElementById('sign-out-button').disabled = true;
    document.getElementById('sign-out-button').innerHTML = 'Processing...';
    fetch('/api/v1/auth/sign-out', {
        method: 'POST',
        headers: {
            'X-ProjectRexa-CSRFToken': csrfToken()
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                setTimeout(() => {
                    // Add a new parameter brodcast to the URL to indicate that the user has signed out
                    let urlParams = new URLSearchParams(window.location.search);
                    urlParams.set('broadcast', 'You have been signed out successfully');
                    window.location.href = '/auth/sign-in?' + urlParams.toString();
                }, 1000);
            } else {
                createAlert(data.message, 'danger');
                document.getElementById('sign-out-button').disabled = false;
                document.getElementById('sign-out-button').innerHTML = 'Sign Out';
            }
        })
        .catch(error => {
            createAlert('Our internal systems are facing some issues. Please try again later.', 'danger');
            document.getElementById('sign-out-button').disabled = false;
            document.getElementById('sign-out-button').innerHTML = 'Sign Out';
        });
}