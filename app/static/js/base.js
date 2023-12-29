document.onreadystatechange = function () {
    if (document.readyState == "complete") {


        let alert = new URLSearchParams(window.location.search).get('alert');
        let alertType = new URLSearchParams(window.location.search).get('alertType');

        if (alert) {
            createAlert(alert, alertType);
        }
    }
}

function createAlert(alert, alertType = "info") {
    if (alertType === null) {
        alertType = "info";
    }

    let alertContainer = document.getElementById('alert-container');
    let alertElement = document.getElementById('alert');

    clearTimeout(alertElement.timer);

    if (alertContainer.style.display !== 'none') {
        alertElement.style.opacity = '0';
        alertContainer.classList.remove('active');
    }

    let alertMessage = document.getElementById('alert-message');
    alertMessage.innerHTML = alert;

    alertElement.classList.remove('alert-success', 'alert-info', 'alert-warning', 'alert-danger');
    alertElement.classList.add('alert-' + alertType);
    alertContainer.classList.add('active');
    alertElement.style.opacity = '1';

    alertElement.timer = setTimeout(function () {
        alertElement.style.opacity = '0';
        alertContainer.classList.remove('active');
    }, 3000);
}

function closeAlert() {
    let alertContainer = document.getElementById('alert-container');
    alertContainer.classList.remove('active');
}


function generateReCaptcha(actionName) {
    return new Promise(function (resolve, reject) {
        grecaptcha.ready(function () {
            grecaptcha.execute('6LdINlonAAAAAK5yArQKUqdHU7sIM8lWD_t_ttOU', { action: actionName })
                .then(function (token) {
                    resolve(token);
                })
                .catch(function (error) {
                    createAlert("Unable to generate reCaptcha token, please refresh the page and try again", 'danger');
                    reject(error);
                });
        });
    });
}