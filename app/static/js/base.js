document.onreadystatechange = function () {
    if (document.readyState == "complete") {

        let alert = new URLSearchParams(window.location.search).get('alert');
        let alertType = new URLSearchParams(window.location.search).get('alertType');

        if (alert) {
            createAlert(alert, alertType);
        }
    }
}

createAlert = function (alert, alertType) {
    let alertMessage = document.getElementById('alert-message');
    alertMessage.innerHTML = alert;

    alertMessage.classList.add('alert-' + alertType);

    document.getElementById('alert-container').setAttribute('style', 'display: block');
}