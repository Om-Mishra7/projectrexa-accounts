'''
    This file contains the main application logic and routes for the application.
'''
import datetime
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
from itsdangerous import URLSafeSerializer, BadSignature
import boto3
from flask import Flask, request, make_response, redirect, url_for, jsonify, render_template, send_from_directory, flash
from app.functions import create_redis_database_connection, create_mongoDB_database_connection, generate_session, get_session, generate_token, send_mail, verify_recaptcha, verify_hashed_password, hash_password, generate_user_id, get_active_sessions, deleter_all_sessions
from app.config import get_config


# Application monitoring configuration
# sentry_sdk.init(
#     dsn=config.sentry_dsn,
#     traces_sample_rate=0.1,
# )

app = Flask(__name__)

config = get_config()

# S3 configuration

s3 = boto3.resource(
    service_name='s3',
    aws_access_key_id='Uf6oBAfEo3b9apub',
    aws_secret_access_key=config.s3_secret_access_key,
    endpoint_url='https://s3.tebi.io',
    verify=False,
    # Set the signature version to the previous version
    config=boto3.session.Config(signature_version='s3'),
)


limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"],
    headers_enabled=True,
    strategy='moving-window',
    storage_uri=config.redis_url,
)


redis_client, mongoDB_client = create_redis_database_connection(
), create_mongoDB_database_connection()

app.config['SECRET_KEY'] = config.secret_key
serializer = URLSafeSerializer(config.secret_key)

mongoDB_cursor = mongoDB_client['starry_night']


# Function to set headers

@app.after_request
def set_headers(response):
    '''
        This function sets the cache control headers for the response.
    '''
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Powered-By'] = 'Cerberus'
    response.headers['Permissions-Policy'] = 'interest-cohort=()'
    return response


# Application routes

@app.route('/favicon.ico')
def favicon():
    '''
        This function returns the favicon for the application.
    '''
    return send_from_directory('static/images', 'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/')
def index():
    '''
        This function returns the index page for the application.
    '''
    session = get_session(request)
    if session is None or not session.is_authenticated():
        response = make_response(redirect(url_for('sign_in')), 302)
        response.set_cookie('X-Identity', '', httponly=True,
                            secure=True, samesite='Lax', expires=0)
        return response
    try:
        try:
            serializer.loads(request.cookies.get('X-Identity'))
            return redirect(url_for('account'), 302)
        except BadSignature:
            response = make_response(redirect(url_for('sign_in')), 302)
            response.set_cookie('X-Identity', '', httponly=True, secure=True, samesite='Lax',
                                expires=0, domain=config.authority)
    except:
        return make_response(jsonify({"message": "We are experiencing some issues, please try again later"}), 500)


@app.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    '''
        This function returns the sign in page for the application.
    '''
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('index'), 302)

    return make_response(render_template('sign_in.html'), 200)


@app.route('/api/auth/sign-in', methods=['POST'])
def api_signin():
    '''
        This function handles the sign in process for the application.
    '''
    if request.method == 'POST':

        # Initial login checks
        try:
            request_data = request.get_json()
            email = request_data['email'].lower()
            password = request_data['password']

            if email is None or password is None:
                return make_response(jsonify({"message": "Email / Password is missing"}), 400)

            if config.recaptcha:
                recaptcha_response = request_data['recaptcha_response']

                if recaptcha_response is None:
                    return make_response(jsonify({"message": "Recaptcha is missing, please try again"}), 400)

                if not verify_recaptcha(recaptcha_response):
                    return make_response(jsonify({"message": "Recaptcha is invalid, please try again"}), 400)
        except:
            return make_response(jsonify({"message": "Invalid Request, please try again"}), 400)

        # Database checks
        try:
            user = mongoDB_cursor['users'].find_one({"email": email})

            if user is None:
                return make_response(jsonify({"message": "This email is not registered"}), 400)
            
            if user['method'] != 'email':
                return make_response(jsonify({"message": "This email was registered with a social method"}), 400)

            if user['verified'] is False:
                return make_response(jsonify({"message": "Email is not verified, please check your inbox or request a <a href='/resend-verification' class='danger-link'>new verification email</a>"}), 400)

            if user['status'] != 'active':
                return make_response(jsonify({"message": "Account is suspended, please contact support"}), 400)

            if verify_hashed_password(password, user['password']):
                response = make_response(
                    jsonify({"message": "Logged in successfully"}), 200)

                response.set_cookie('X-Identity', generate_session(user, request), httponly=True, secure=True, samesite='Lax',
                                    expires=datetime.datetime.utcnow() + datetime.timedelta(days=180), domain=config.authority)
                return response

            return make_response(jsonify({"message": "Email / Password is incorrect"}), 400)

        except:
            return make_response(jsonify({"message": "We are experiencing some issues, please try again later"}), 500)


@ app.route('/sign-up', methods=['GET', 'POST'])
def signup():
    '''
        This function returns the sign up page for the application.
    '''
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('index'), 302)

    return make_response(render_template('sign_up.html'), 200)


@ app.route('/api/auth/sign-up', methods=['POST'])
def api_signup():
    '''
        This function handles the sign up process for the application.
    '''
    try:
        if request.method == 'POST':

            request_data = request.get_json()

            username = request_data['username'].title()
            email = request_data['email'].lower()
            password = request_data['password']

            if email is None or password is None or username is None:
                return make_response(jsonify({"message": "Email / Password / Username is missing"}), 400)

            if config.recaptcha:
                recaptcha_response = request_data['recaptcha_response']

                if recaptcha_response is None:
                    return make_response(jsonify({"message": "Recaptcha is missing, please try again"}), 400)

                if not verify_recaptcha(recaptcha_response):
                    return make_response(jsonify({"message": "Recaptcha is invalid, please try again"}), 400)

            if mongoDB_cursor['users'].find_one({"email": email}) is not None:
                return make_response(jsonify({"message": "This email is already registered"}), 400)

            mongoDB_cursor['users'].insert_one(
                {"email": email, "password": hash_password(password), "method": "email", "user_id": generate_user_id(), "verified": False, "name": username.title(), "profile_picture": "https://source.boringavatars.com/beam/100", "role": "user", "status": "active", "created_at": datetime.datetime.utcnow(), "last_login": datetime.datetime.utcnow()})

            user = mongoDB_cursor['users'].find_one({"email": email})

            token = generate_token(user, 'verify_email')
            send_mail(user, token, 'verify_email')
            flash(
                "Account has been created successfully, please check your inbox to verify your email")
            return make_response(jsonify({"message": "The account has been created successfully, please check your inbox to verify your email"}), 200)

    except:
        return make_response(jsonify({"message": "Invalid Request, please try again"}), 400)


@ app.route('/sign-out')
def sign_out():
    '''
        This function signs out the user.
    '''
    session = get_session(request)
    if session is None or not session.is_authenticated():
        return redirect(url_for('index'), 302)

    response = make_response(redirect(url_for('sign_in')), 302)

    try:
        session_id = serializer.loads(request.cookies.get('X-Identity'))
        redis_client.delete(session_id)
    except BadSignature:
        pass
    response = make_response(redirect(url_for('sign_in')), 302)
    response.set_cookie('X-Identity', '', httponly=True,
                        secure=True, samesite='Lax', expires=0)
    return response


@ app.route('/oauth/github')
def github_oauth():
    '''
        This function redirects the user to GitHub for authentication.
    '''
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('index'))
    secret_cookie = secrets.token_hex(32)
    state = secrets.token_hex(32)
    redis_client.set(secret_cookie, state, ex=300)
    response = make_response(redirect(
        f'https://github.com/login/oauth/authorize?client_id={config.github_client_id}&redirect_uri={config.github_redirect_uri}&state={state}'))
    response.set_cookie('X-GitHub-State', secret_cookie, httponly=True, secure=True,
                        samesite='Lax', expires=datetime.datetime.utcnow() + datetime.timedelta(seconds=300))
    return response


@ app.route('/callback/github')
def github_callback():
    '''
        This function handles the callback from GitHub.
    '''
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('index'))
    try:
        code = request.args.get('code')
        state = request.args.get('state')

        if code is None or state is None:
            flash("The request has timed out, please try again")
            return make_response(redirect(url_for('sign_in')), 302)

        try:
            if str(state) != str(redis_client.get(request.cookies.get('X-GitHub-State'))):
                flash("The request has timed out, please try again")
                return make_response(redirect(url_for('sign_in')), 302)

            redis_client.delete(request.cookies.get('X-GitHub-State'))

        except:
            flash("The request has timed out, please try again")
            return make_response(redirect(url_for('sign_in')), 302)

        response = requests.post(f'https://github.com/login/oauth/access_token?client_id={config.github_client_id}&client_secret={config.github_client_secret}&code={code}', headers={
                                 'Accept': 'application/json'}, timeout=3)

        user_data = requests.get('https://api.github.com/user', headers={
                                 'Authorization': f'Bearer {response.json()["access_token"]}'}, timeout=3).json()

        if user_data['email'] is None:
            email = requests.get('https://api.github.com/user/emails', headers={
                'Authorization': f'Bearer {response.json()["access_token"]}'}, timeout=3).json()
            for record in email:
                if record['primary'] is True:
                    user_data['email'] = record['email']
                    break

        user_local = mongoDB_cursor['users'].find_one(
            {"user_id": user_data['id']})

        account_id_registered_with_email = mongoDB_cursor['users'].find_one(
            {"email": user_data['email']})

        if account_id_registered_with_email is not None:
            if account_id_registered_with_email['user_id'] != user_data['id']:
                flash("This email is already registered with another account")
                return make_response(redirect(url_for('sign_in')), 302)

        if user_local is None:
            mongoDB_cursor['users'].insert_one({"user_id": user_data['id'], "email": user_data['email'], "method": "github", "name": user_data[
                                               'name'].title(), "profile_picture": f'https://cdn.projectrexa.dedyn.io/user-content/avatars/{user_data["id"]}.png', "role": "user", "last_login": datetime.datetime.utcnow(), "created_at": datetime.datetime.utcnow(), "status": "active", "verified": True})

        user_local = mongoDB_cursor['users'].find_one(
            {"user_id": user_data['id']})

        profile_picture_data = requests.get(
            user_data['avatar_url'], timeout=3).content

        s3.Bucket('cdn.projectrexa.dedyn.io').put_object(
            Key=f'user-content/avatars/{user_local["user_id"]}.png', Body=profile_picture_data, ACL='public-read', ContentType='image/png')

        if user_local['method'] != 'github':
            flash("This email is already registered with another method")
            return make_response(redirect(url_for('sign_in')), 302)

        if user_local['status'] == 'suspended':
            flash("Account is suspended, please contact support")
            return make_response(redirect(url_for('sign_in')), 302)

        mongoDB_cursor['users'].update_one({"email": user_local['email']}, {
            "$set": {"last_login": datetime.datetime.utcnow()}})

        response = make_response((redirect(url_for('index'))), 302)
        response.set_cookie(
            'X-Identity', generate_session(user_local, request), httponly=True, secure=True, samesite='Lax', expires=datetime.datetime.utcnow() + datetime.timedelta(days=30), domain=config.authority)
        return response

    except Exception as e:
        print(e)
        flash("Unable to login with GitHub, please try again later")
        return make_response(redirect(url_for('sign_in')), 302)


@ app.route('/oauth/google')
def google_oauth():
    '''
        This function redirects the user to Google for authentication.
    '''
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('index'))
    secret_cookie = secrets.token_hex(32)
    state = secrets.token_hex(32)
    redis_client.set(secret_cookie, state, ex=300)
    response = make_response(redirect(
        f'https://accounts.google.com/o/oauth2/v2/auth?client_id=638350246071-dsj9thj6g6m1rjvh9krautaqbjh00ini.apps.googleusercontent.com&redirect_uri={config.google_redirect_uri}&response_type=code&scope=email%20profile&state={state}'))
    response.set_cookie('X-Google-State', secret_cookie, httponly=True, secure=True,
                        samesite='Lax', expires=datetime.datetime.utcnow() + datetime.timedelta(seconds=300))
    return response


@ app.route('/callback/google')
def google_callback():
    '''
        This function handles the callback from Google.
    '''
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('index'))
    try:
        code = request.args.get('code')
        state = request.args.get('state')

        try:
            if str(state) != str(redis_client.get(request.cookies.get('X-Google-State'))):
                flash("The request has timed out, please try again")
                return make_response(redirect(url_for('sign_in')), 302)

            redis_client.delete(request.cookies.get('X-Google-State'))

        except:
            flash("The request has timed out, please try again")
            return make_response(redirect(url_for('sign_in')), 302)

        response = requests.post(f'https://oauth2.googleapis.com/token?code={code}&client_id=638350246071-dsj9thj6g6m1rjvh9krautaqbjh00ini.apps.googleusercontent.com&client_secret={config.google_client_secret}&redirect_uri={config.google_redirect_uri}&grant_type=authorization_code', headers={
                                 'Accept': 'application/json'}, timeout=3)

        user_data = requests.get(
            f'https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token={response.json()["access_token"]}', timeout=3).json()

        user_local = mongoDB_cursor['users'].find_one(
            {"email": user_data['email']})

        user_id = generate_user_id()
        if user_local is None:
            mongoDB_cursor['users'].insert_one({"user_id": user_id, "email": user_data['email'], "method": "google", "name": user_data[
                                               'name'].title(), "profile_picture": f'https://cdn.projectrexa.dedyn.io/user-content/avatars/{user_id}.png', "role": "user", "last_login": datetime.datetime.utcnow(), "created_at": datetime.datetime.utcnow(), "status": "active", "verified": True})
            user_local = mongoDB_cursor['users'].find_one(
                {"email": user_data['email']})

            profile_picture_data = requests.get(
                user_data['picture'], timeout=3).content

            s3.Bucket('cdn.projectrexa.dedyn.io').put_object(
                Key=f'user-content/avatars/{user_local["user_id"]}.png', Body=profile_picture_data, ACL='public-read', ContentType='image/png')
        else:
            if user_local['method'] != 'google':
                flash("This email is already registered with another method")
                return make_response(redirect(url_for('sign_in')), 302)

            if user_local['status'] == 'suspended':
                flash("Account is suspended, please contact support")
                return make_response(redirect(url_for('sign_in')), 302)

            mongoDB_cursor['users'].update_one({"email": user_local['email']}, {
                                               "$set": {"last_login": datetime.datetime.utcnow()}})

        response = make_response((redirect(url_for('index'))), 302)
        response.set_cookie(
            'X-Identity', generate_session(user_local, request), httponly=True, secure=True, samesite='Lax', expires=datetime.datetime.utcnow() + datetime.timedelta(days=30), domain=config.authority)
        return response

    except Exception as e:
        print(e)
        flash("Unable to login with Google, please try again later")
        return make_response(redirect(url_for('sign_in')), 302)


@ app.route('/verify-email')
def verify_email():
    '''
        This function verifies the email of the user.
    '''

    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('index'))
    try:
        token = request.args.get('token')
        if token is None:
            flash("Invalid token, please request a new verification email by logging in")
            return make_response(redirect(url_for('sign_in')), 302)

        token = serializer.loads(token)

        token_info = mongoDB_cursor['tokens'].find_one(
            {"token": token, "scope": "verify_email"})

        if token_info is None:
            flash("Invalid token, please request a new verification email by logging in")
            return make_response(redirect(url_for('sign_in')), 302)

        if token_info['expires_at'] < datetime.datetime.utcnow():
            flash(
                "Token has expired, please request a new verification email by logging in")
            return make_response(redirect(url_for('sign_in')), 302)

        user_info = mongoDB_cursor['users'].find_one(
            {"user_id": token_info['user_id']})

        if user_info['verified'] is True:
            flash("Email has already been verified, you can now login")
            return make_response(redirect(url_for('sign_in')), 302)

        mongoDB_cursor['users'].update_one({"user_id": token_info['user_id']}, {
            "$set": {"verified": True}})
        mongoDB_cursor['tokens'].delete_one(
            {"token": token, "scope": "verify_email"})

        flash("Email has been verified successfully, you can now login")
        return make_response(redirect(url_for('sign_in')), 302)

    except:
        flash("Invalid Request, please try again")
        return make_response(redirect(url_for('sign_in')), 302)


@ app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    '''
        This function resends the verification email for the user.
    '''
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return make_response(redirect(url_for('index')), 302)
    return make_response(render_template('resend_verification.html'), 200)


@ app.route('/api/auth/resend-verification', methods=['POST'])
def api_resend_verification():
    '''
        This function handles the resend verification email process for the user.
    '''
    try:
        request_data = request.get_json()
        email = request_data['email']
        if verify_recaptcha(request_data['recaptcha_response']):
            if email is None:
                return make_response(jsonify({"message": "Please enter an valid email"}), 400)
            user_info = mongoDB_cursor['users'].find_one({"email": email})
            if user_info is None:
                return make_response(jsonify({"message": "This email is not registered"}), 400)
            if user_info['method'] != 'email':
                return make_response(jsonify({"message": "This email has already been verified"}), 400)
            if user_info['verified'] is True:
                return make_response(jsonify({"message": "This email has already been verified"}), 400)
            if user_info['status'] == 'suspended':
                return make_response(jsonify({"message": "Account is suspended, please contact support"}), 400)
            mongoDB_cursor['tokens'].delete_many(
                {"user_id": user_info['user_id'], "scope": "verify_email"})
            token = generate_token(user_info, 'verify_email')
            if not send_mail(user_info, token, 'verify_email'):
                return make_response(jsonify({"message": "Unable to send email, please try again later"}), 500)
            return make_response(jsonify({"message": "Verification email has been sent successfully"}), 200)

        return make_response(jsonify({"message": "Recaptcha is invalid, please try again"}), 400)
    except:
        return make_response(jsonify({"message": "Invalid Request, please try again"}), 400)


@ app.route('/account')
def account():
    '''
        This function returns the account page for the user.
    '''
    session = get_session(request)
    if session is None or not session.is_authenticated():
        return redirect(url_for('sign_in'), 302)

    user_info = mongoDB_cursor['users'].find_one({"user_id": session.user_id})
    sessions = get_active_sessions(session.user_id)
    if user_info is None or not sessions:
        response = make_response(redirect(url_for('sign_in')), 302)
        response.set_cookie('X-Identity', '', httponly=True,
                            secure=True, samesite='Lax', expires=0)
        return response
    return make_response(render_template('account.html', user_info=user_info, sessions=sessions, session_id=session.session_id), 200)


@ app.route('/api/auth/remove_session', methods=['POST'])
def remove_session():
    '''
        This function removes a session for the user.
    '''
    session = get_session(request)
    if session is None or not session.is_authenticated():
        return make_response(jsonify({"message": "You are not authenticated"}), 401)
    try:
        request_data = request.get_json()
        logout_token = request_data['logout_token']
        if logout_token is None:
            return make_response(jsonify({"message": "Logout token is missing"}), 400)
        logout_token = serializer.loads(logout_token)
        redis_client.delete(logout_token)
        return make_response(jsonify({"message": "Session has been removed successfully"}), 200)
    except:
        return make_response(jsonify({"message": "Invalid Request, please try again"}), 400)


@ app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    '''
        This function returns the forgot password page for the user.
    '''
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('index'), 302)
    if request.method == 'POST':
        request_data = request.get_json()
        email = request_data['email']
        if not verify_recaptcha(request_data['recaptcha_response']):
            return make_response(jsonify({"message": "Recaptcha is invalid, please try again"}), 400)
        if email is None:
            return make_response(jsonify({"message": "Please enter an valid email"}), 400)
        user_info = mongoDB_cursor['users'].find_one({"email": email})
        if user_info is None:
            return make_response(jsonify({"message": "This email is not registered"}), 400)
        if user_info['method'] != 'email':
            return make_response(jsonify({"message": "This email was registered with a social method"}), 400)
        if user_info['verified'] is False:
            return make_response(jsonify({"message": "This email is not verified, please check your inbox or request a new verification email"}), 400)
        if user_info['status'] == 'suspended':
            return make_response(jsonify({"message": "Account is suspended, please contact support"}), 400)
        mongoDB_cursor['tokens'].delete_many(
            {"user_id": user_info['user_id'], "scope": "reset_password"})
        token = generate_token(user_info, 'reset_password')
        if not send_mail(user_info, token, 'forgot_password'):
            return make_response(jsonify({"message": "Unable to send email, please try again later"}), 500)
        flash("Password reset email has been sent successfully")
        return make_response(jsonify({"message": "Password reset email has been sent successfully"}), 200)
    return make_response(render_template('forgot_password.html'), 200)


@ app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    '''
        This function returns the reset password page for the user.
    '''
    if request.method == 'POST':
        request_data = request.get_json()
        token = request_data['token']
        password = request_data['password']

        if token is None or password is None:
            return make_response(jsonify({"message": "Token / Password is missing"}), 400)
        if not verify_recaptcha(request_data['recaptcha_response']):
            return make_response(jsonify({"message": "Recaptcha is invalid, please try again"}), 400)
        token = serializer.loads(token)
        token_info = mongoDB_cursor['tokens'].find_one(
            {"token": token, "scope": "reset_password"})
        if token_info is None:
            return make_response(jsonify({"message": "Invalid Token, please try again"}), 400)
        if token_info['expires_at'] < datetime.datetime.utcnow():
            return make_response(jsonify({"message": "Token has expired, please request a new one"}), 400)
        user_info = mongoDB_cursor['users'].find_one(
            {"user_id": token_info['user_id']})
        if user_info is None:
            return make_response(jsonify({"message": "Invalid Token, please try again"}), 400)
        if user_info['method'] != 'email':
            return make_response(jsonify({"message": "This email was registered with a social method"}), 400)
        if user_info['verified'] is False:
            return make_response(jsonify({"message": "This email is not verified, please check your inbox or request a new verification email"}), 400)
        if user_info['status'] == 'suspended':
            return make_response(jsonify({"message": "Account is suspended, please contact support"}), 400)
        if get_session(request) is not None and get_session(request).user_id != user_info['user_id']:
            return make_response(jsonify({"message": "You are trying to reset password for another account"}), 400)
        if verify_hashed_password(password, user_info['password']):
            return make_response(jsonify({"message": "New password cannot be the same as the old one"}), 400)
        if not deleter_all_sessions(user_info['user_id']):
            return make_response(jsonify({"message": "Unable to delete sessions, please try again later"}), 500)
        mongoDB_cursor['users'].update_one({"user_id": token_info['user_id']}, {
            "$set": {"password": hash_password(password)}})
        mongoDB_cursor['tokens'].delete_many(
            {"user_id": user_info['user_id'], "scope": "reset_password"})
        flash("Password has been reset successfully, you can now login")
        return make_response(jsonify({"message": "Password has been reset successfully, you can now login"}), 200)
    token = request.args.get('token')
    if token is None:
        return make_response(redirect(url_for('index')), 302)
    try:
        token = serializer.loads(token)
    except BadSignature:
        flash("Invalid Token, please try again")
        return make_response(redirect(url_for('index')), 302)
    return make_response(render_template('reset_password.html', token=token), 200)


@ app.route('/version')
def version():
    return jsonify({"version": "1.0.0"})


@ app.errorhandler(404)
def page_not_found(e):
    return make_response(jsonify({"message": "Page not found"}), 404)


@ app.errorhandler(500)
def internal_server_error(e):
    response = make_response(
        jsonify({"message": "Internal server error"}), 500)
    response.set_cookie('X-Identity', '', expires=0)
    return response

