const created_at = document.getElementsByClassName('created_at');

for (let i = 0; i < created_at.length; i++) {
    let date = new Date(created_at[i].innerHTML);
    created_at[i].innerHTML = date.toLocaleDateString('en-US', {year: 'numeric', month: 'long', day: 'numeric' });
}
function remove_session(this) {
    this.innerHTML = 'Logging out...';
    this.disabled = true;
    const logout_token = this.getAttribute('data-logout-token');
    fetch('/api/remove_session', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
        , body: JSON.stringify({ logout_token: logout_token })
    }).then((response) => {
        if (response.status === 200) {
            this.parentNode.remove();
        }
        else {
            this.innerHTML = 'Logout';
            this.disabled = false;
        }
    }
    );
}