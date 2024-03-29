let alertTimeout;

function createAlert(message, type) {
    // Clear existing timeout
    clearTimeout(alertTimeout);

    // Remove existing alert container if present
    const existingAlert = document.getElementById('alert-container');
    if (existingAlert) {
        existingAlert.remove();
    }

    // Create new alert element
    let alert = document.createElement('div');
    alert.setAttribute('id', 'alert-container');
    alert.classList.add('alert', `alert-${type}`);
    alert.innerHTML = message;
    document.body.insertBefore(alert, document.body.firstChild);

    // Trigger animation for showing alert
    document.getElementById('alert-container').animate([
        { translateY: '-100px', opacity: 0 },
        { translateY: '0px', opacity: 1 }
    ], {
        duration: 500,
        iterations: 1
    });

    // Set timeout to remove alert after 5 seconds
    alertTimeout = setTimeout(() => {
        let fadeOutAnimation = document.getElementById('alert-container').animate([
            { translateY: '0px', opacity: 1 },
            { translateY: '-100px', opacity: 0 }
        ], {
            duration: 500,
            iterations: 1
        });

        // Remove alert after fade-out animation completes
        fadeOutAnimation.onfinish = () => {
            document.getElementById('alert-container').remove();
        };
    }, 5000);
}


function csrfToken() {
    let cookies = document.cookie.split(';');
    let csrfToken = '';
    cookies.forEach(cookie => {
        if (cookie.includes('X-ProjectRexa-CSRFToken')) {
            csrfToken = cookie.split('=')[1];
        }
        else {
            createAlert('The CSRF token is missing. Please refresh the page, or disable your browser extensions.', 'danger');
        }
    });
    return csrfToken;
}

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const broadcastMessage = urlParams.get('broadcast');
    if (broadcastMessage) {
        createAlert(broadcastMessage, 'info');
    }
});