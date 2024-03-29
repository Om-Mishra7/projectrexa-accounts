from application.config import Config
from flask import Flask, request, jsonify, render_template, redirect, url_for, g
from application.helpers import generate_guest_session, load_cookie_session
from application.authentication import handle_email_signup, handle_email_signin, handle_user_signout, handle_email_verification, handle_resend_email_verification, handle_send_password_reset, handle_reset_password



app = Flask(__name__, static_url_path='/static', static_folder='static', template_folder='src')

Config = Config()

# Application Configuration

app.config['DEBUG'] = Config.enviroment_info['debug']
app.config['HOST'] = Config.enviroment_info['host']
app.config['PORT'] = Config.enviroment_info['port']

app.config['SECRET_KEY'] = Config.secret_key


# Application Middleware 

@app.before_request
def before_request():
    # If the user information is not avialable in the global context, then check if the user has a session cookie and set the user information in the global context if the session cookie is valid
    session_cookie = request.cookies.get('X-ProjectRexa-Session')
    if session_cookie is not None:
        # Load the session from the cookie
        session = load_cookie_session(request, Config.redis_connection, session_cookie)
        if session is not None:
            g.session = session
            return

        # If no valid session cookie found, generate a guest session
    g.session = generate_guest_session(request, Config.redis_connection)

@app.before_request
def csrf_protect():
    # If the request is not a GET request, then check if the CSRF token is valid
    if request.method != 'GET':
        csrf_token = request.headers.get('X-ProjectRexa-CSRFToken')
        if csrf_token is None or csrf_token != g.session['session_info']['session_csrf_token']:
            return jsonify({'status': 'error', 'message': 'The CSRF token is invalid'}), 400

@app.after_request
def after_request(response):
    # Set the session cookie in the response
    response.set_cookie('X-ProjectRexa-Session', g.session['session_id'], max_age=60*60*24*180, httponly=True, secure=True)
    response.set_cookie('X-ProjectRexa-CSRFToken', g.session['session_info']['session_csrf_token'])
    response.headers['X-Server'] = f'ProjectRexa/v{Config.application_info["version"]}'
    return response

# Application Decorators
def login_required(func):
    def wrapper(*args, **kwargs):
        if g.session['session_info']['session_type'] == 'guest':
            return redirect(url_for('sign_up', next=request.url))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def guest_required(func):
    def wrapper(*args, **kwargs):
        if g.session['session_info']['session_type'] != 'guest':
            return redirect(url_for('home')), 302
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# App Custom Context
@app.context_processor
def inject_query_params():
    query_params = request.args.to_dict(flat=False)
    if 'broadcast' in query_params: # Prevent the broadcast query parameter from being continued to passed to the templates
        query_params.pop('broadcast')
    if len(query_params) > 0:
        query_string = ""
        for key, value in query_params.items():
            query_string += f'{key}={value[0]}&'
            print(query_string)
        return dict(query_params=query_string[:-1])
    return dict()

# Application Routes

@app.route('/')
@login_required
def home():
    return jsonify(g.session)

@app.route('/auth/sign-up', methods=['GET'])
@guest_required
def sign_up():
    return render_template('sign-up.html')

@app.route('/auth/sign-up/identifier/email', methods=['GET'])
@guest_required
def sign_up_email():
    return render_template('sign-up-email.html')

@app.route('/auth/sign-in', methods=['GET'])
@guest_required
def sign_in():
    return render_template('sign-in.html')

@app.route('/auth/sign-out', methods=['GET'])
@login_required
def sign_out():
    return render_template('sign-out.html')
    
@app.route('/auth/email/verification/verify', methods=['GET'])
@guest_required
def verify_email():
    return handle_email_verification(request, g, Config.database_cursor, Config.redis_connection)

@app.route('/auth/email/verification/resend', methods=['GET'])
@guest_required
def resend_email_verification():
    return handle_resend_email_verification(request, g, Config.database_cursor)

@app.route('/auth/password/forgot-password', methods=['GET'])
@guest_required
def send_password_reset():
    return handle_send_password_reset(request, g, Config.database_cursor)

@app.route('/auth/password/reset-password', methods=['GET'])
@guest_required
def reset_password():
    return render_template('reset-password.html', password_reset_token = request.args.get('reset_token'))



# Utility Routes

@app.route('/favicon.ico')
def favicon():
    return redirect('https://cdn.om-mishra.com/favicon.ico'), 302


# API Routes
@app.route('/api/v1/auth/sign-up/email', methods=['POST'])
@guest_required
def api_signup():
    return handle_email_signup(request, Config.database_cursor)

@app.route('/api/v1/auth/sign-in/email', methods=['POST'])
@guest_required
def api_signup_verification():
    return handle_email_signin(request, Config.database_cursor, Config.redis_connection, g)

@app.route('/api/v1/auth/sign-out', methods=['POST'])
@login_required
def api_signout():
    return handle_user_signout(request, Config.redis_connection, Config.database_cursor, g)

@app.route('/api/v1/auth/password/reset-password', methods=['POST'])
@guest_required
def api_reset_password():
    return handle_reset_password(request, g, Config.database_cursor, Config.redis_connection)