const created_at = document.getElementsByClassName('created_at');

for (let i = 0; i < created_at.length; i++) {
    let date = new Date(created_at[i].innerHTML);
    created_at[i].innerHTML = date.toLocaleDateString('en-US', {year: 'numeric', month: 'long', day: 'numeric' });
}

const logout_button = document.getElementsByClassName('logout_button');

for (let i = 0; i < logout_button.length; i++) {

    logout_button[i].addEventListener('click', () => {
        const logout_token = logout_button[i].getAttribute('data-logout-token');
        logout_button[i].innerHTML = 'Logging out...';
        logout_button[i].disabled = true;
        fetch('/api/remove_session', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
            , body: JSON.stringify({ logout_token: logout_token })
        }).then((response) => {
            if (response.status === 200) {
                logout_button[i].parentNode.remove();
            }
            else {
                logout_button[i].innerHTML = 'Logout';
                logout_button[i].disabled = false;
            }
        });
    });
}