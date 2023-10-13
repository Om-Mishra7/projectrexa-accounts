const created_at = document.getElementsByClassName('created_at');

for (let i = 0; i < created_at.length; i++) {
    let date = new Date(created_at[i].innerHTML);
    created_at[i].innerHTML = date.toLocaleDateString('en-US', {year: 'numeric', month: 'long', day: 'numeric' });
}

function remove_session(logout_token) {
    const logout_button = document.querySelectorAll(`button[data-logout-token="${logout_token}"]`)[0];

    logout_button.innerHTML = 'Logging out...';
    logout_button.disabled = true;
    fetch('/api/auth/remove_session', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
        , body: JSON.stringify({ logout_token: logout_token })
    }).then((response) => {
        if (response.status === 200) {
            logout_button.parentNode.remove();
        }
        else {
            logout_button.innerHTML = 'Logout';
            logout_button.disabled = false;
        }
    }
    );
}