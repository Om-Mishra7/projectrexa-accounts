from app.database import create_redis_database_connection, create_mongoDB_database_connection
from app.config import get_config
from app.functions import hash_password, verify_hashed_password, verify_recaptcha, generate_session, get_session, generate_user_id, generate_token, send_mail, get_active_sessions, deleter_all_sessions
from flask import request, jsonify, make_response, Blueprint, render_template, redirect, url_for, send_from_directory, flash
import secrets
import requests
import datetime
from itsdangerous import URLSafeSerializer, BadSignature


config = get_config()

serializer = URLSafeSerializer(config.secret_key)

redis_client, mongoDB_client = create_redis_database_connection(
), create_mongoDB_database_connection()

mongoDB_cursor = mongoDB_client['starry_night']

routes = Blueprint('routes', __name__)


@routes.route('/favicon.ico')
def favicon():
    return send_from_directory('static/images', 'favicon.ico', mimetype='image/vnd.microsoft.icon')


@routes.route('/')
def index():
    session = get_session(request)
    if session is None or not session.is_authenticated():
        response = make_response(redirect(url_for('routes.sign_in')), 302)
        response.set_cookie('X-Identity', '', httponly=True,
                            secure=True, samesite='Lax', expires=0)
        return response
    try:

        try:
            session_id = serializer.loads(request.cookies.get('X-Identity'))
        except BadSignature:
            return redirect(url_for('routes.sign_in'))
        return make_response(redirect(url_for('routes.account')), 302)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "We are experiencing some issues, please try again later"}), 500)


@routes.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'), 302)
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
        except Exception as e:
            return make_response(jsonify({"message": "Invalid Request, please try again"}), 400)

        # Database checks
        try:
            user = mongoDB_cursor['users'].find_one({"email": email})

            if user is None or user['method'] != 'email':
                return make_response(jsonify({"message": "Email / Password is incorrect"}), 400)

            if verify_hashed_password(password, user['password']) and user['verified'] == True and user['status'] == 'active':
                response = make_response(
                    jsonify({"message": "{} logged in successfully".format(user['email'])}), 200)
                response.set_cookie('X-Identity', generate_session(user, request), httponly=True, secure=True, samesite='Lax',
                                    expires=datetime.datetime.utcnow() + datetime.timedelta(days=30), domain=config.authority)
                return response

            elif user['verified'] == False:
                return make_response(jsonify({"message": "Email is not verified, please check your inbox or request a <a href='/resend-verification' class='danger-link'>new verification email</a>"}), 400)

            elif user['status'] == 'suspended':
                return make_response(jsonify({"message": "Account is suspended, please contact support"}), 400)

            else:
                return make_response(jsonify({"message": "Email / Password is incorrect"}), 400)

        except:
            return make_response(jsonify({"message": "We are experiencing some issues, please try again later"}), 500)

    return make_response(render_template('sign_in.html'), 200)


@routes.route('/sign-up', methods=['GET', 'POST'])
def signup():
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'), 302)
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

    except Exception as e:
        return make_response(jsonify({"message": "Invalid Request, please try again"}), 400)

    return make_response(render_template('sign_up.html'), 200)


@routes.route('/sign-out')
def sign_out():
    session = get_session(request)
    serializer = URLSafeSerializer(config.secret_key)
    if session is None or not session.is_authenticated():
        return redirect(url_for('routes.index'), 302)

    response = make_response(redirect(url_for('routes.sign_in')), 302)

    try:
        session_id = serializer.loads(request.cookies.get('X-Identity'))
        redis_client.delete(session_id)
    except BadSignature:
        pass
    response.set_cookie('X-Identity', '', httponly=True,
                        secure=True, samesite='Lax', expires=0)
    return response


@routes.route('/oauth/github')
def github_oauth():
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'))
    secret_cookie = secrets.token_hex(32)
    state = secrets.token_hex(32)
    redis_client.set(secret_cookie, state, ex=300)
    response = make_response(redirect('https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope=user:email'.format(
        config.github_client_id, config.github_redirect_uri, state)))
    response.set_cookie('X-GitHub-State', secret_cookie, httponly=True, secure=True,
                        samesite='Lax', expires=datetime.datetime.utcnow() + datetime.timedelta(seconds=180))
    return response


@routes.route('/callback/github')
def github_callback():
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'))
    try:
        code = request.args.get('code')
        state = request.args.get('state')

        try:
            if str(state) != str(redis_client.get(request.cookies.get('X-GitHub-State'))):
                flash("The url was tampered with, please try again")
                return make_response(redirect(url_for('routes.sign_in')), 302)

            redis_client.delete(request.cookies.get('X-GitHub-State'))

        except Exception as e:
            flash("The url was tampered with, please try again")
            return make_response(redirect(url_for('routes.sign_in')), 302)

        response = requests.post('https://github.com/login/oauth/access_token?client_id={}&client_secret={}&code={}&redirect_uri={}'.format(
            config.github_client_id, config.github_client_secret, code, config.github_redirect_uri), headers={'Accept': 'application/json'})

        user_data = requests.get('https://api.github.com/user', headers={
                                 'Authorization': 'Bearer {}'.format(response.json()['access_token'])}).json()

        if user_data['email'] is None:
            email = requests.get('https://api.github.com/user/emails', headers={
                'Authorization': 'Bearer {}'.format(response.json()['access_token'])}).json()
            for record in email:
                if record['primary'] == True:
                    user_data['email'] = record['email']
                    break
        user_private = mongoDB_cursor['users'].find_one(
            {"email": user_data['email']})

        if user_private is None:
            mongoDB_cursor['users'].insert_one({"user_id": generate_user_id(), "email": user_data['email'], "method": "github", "name": user_data[
                                               'name'].title(), "profile_picture": user_data['avatar_url'], "role": "user", "last_login": datetime.datetime.utcnow(), "created_at": datetime.datetime.utcnow(), "status": "active"})
            user_private = mongoDB_cursor['users'].find_one(
                {"email": user_data['email']})
        else:
            if user_private['method'] != 'github':
                flash("This email is already registered with another method")
                return make_response(redirect(url_for('routes.sign_in')), 302)

            mongoDB_cursor['users'].update_one({"email": user_private['email']}, {
                                               "$set": {"last_login": datetime.datetime.utcnow()}})

        response = make_response((redirect(url_for('routes.index'))), 302)
        response.set_cookie(
            'X-Identity', generate_session(user_private, request), httponly=True, secure=True, samesite='Lax', expires=datetime.datetime.utcnow() + datetime.timedelta(days=30), domain=config.authority)
        return response

    except Exception as e:
        flash("Unable to login with GitHub, please try again later")
        return make_response(redirect(url_for('routes.sign_in')), 302)


@routes.route('/oauth/google')
def google_oauth():
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'))
    secret_cookie = secrets.token_hex(32)
    state = secrets.token_hex(32)
    redis_client.set(secret_cookie, state, ex=300)
    response = make_response(redirect('https://accounts.google.com/o/oauth2/v2/auth?client_id=638350246071-dsj9thj6g6m1rjvh9krautaqbjh00ini.apps.googleusercontent.com&redirect_uri={}&response_type=code&scope=https://www.googleapis.com/auth/userinfo.email%20https://www.googleapis.com/auth/userinfo.profile&state={}'.format(
        config.google_redirect_uri, state)))
    response.set_cookie('X-Google-State', secret_cookie, httponly=True, secure=True,
                        samesite='Lax', expires=datetime.datetime.utcnow() + datetime.timedelta(seconds=180))
    return response


@routes.route('/callback/google')
def google_callback():
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'))
    try:
        code = request.args.get('code')
        state = request.args.get('state')

        try:
            if str(state) != str(redis_client.get(request.cookies.get('X-Google-State'))):
                flash("The url was tampered with, please try again")
                return make_response(redirect(url_for('routes.sign_in')), 302)

            redis_client.delete(request.cookies.get('X-Google-State'))

        except Exception as e:
            flash("The url was tampered with, please try again")
            return make_response(redirect(url_for('routes.sign_in')), 302)

        response = requests.post('https://oauth2.googleapis.com/token?code={}&client_id=638350246071-dsj9thj6g6m1rjvh9krautaqbjh00ini.apps.googleusercontent.com&client_secret={}&redirect_uri={}&grant_type=authorization_code'.format(
            code, config.google_client_secret, config.google_redirect_uri), headers={'Accept': 'application/json'})

        user_data = requests.get('https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token={}'.format(
            response.json()['access_token'])).json()

        user_private = mongoDB_cursor['users'].find_one(
            {"email": user_data['email']})

        if user_private is None:
            mongoDB_cursor['users'].insert_one({"user_id": generate_user_id(), "email": user_data['email'], "method": "google", "name": user_data[
                                               'name'].title(), "profile_picture": user_data['picture'], "role": "user", "last_login": datetime.datetime.utcnow(), "created_at": datetime.datetime.utcnow(), "status": "active"})
            user_private = mongoDB_cursor['users'].find_one(
                {"email": user_data['email']})
        else:
            if user_private['method'] != 'google':
                flash("This email is already registered with another method")
                return make_response(redirect(url_for('routes.sign_in')), 302)

            mongoDB_cursor['users'].update_one({"email": user_private['email']}, {
                                               "$set": {"last_login": datetime.datetime.utcnow()}})

        response = make_response((redirect(url_for('routes.index'))), 302)
        response.set_cookie(
            'X-Identity', generate_session(user_private, request), httponly=True, secure=True, samesite='Lax', expires=datetime.datetime.utcnow() + datetime.timedelta(days=30), domain=config.authority)
        return response

    except Exception as e:
        flash("Unable to login with Google, please try again later")
        return make_response(redirect(url_for('routes.sign_in')), 302)


@routes.route('/verify-email')
def verify_email():

    serializer = URLSafeSerializer(config.secret_key)

    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'))
    try:
        token = request.args.get('token')
        if token is None:
            return make_response(jsonify({"message": "Invalid Request, please try again"}), 400)

        token = serializer.loads(token)

        token_info = mongoDB_cursor['tokens'].find_one(
            {"token": token, "scope": "verify_email"})

        if token_info is None:
            return make_response(jsonify({"message": "Invalid Token, please try again"}), 400)

        if token_info['expires_at'] < datetime.datetime.utcnow():
            return make_response(jsonify({"message": "Token has expired, please request a new one"}), 400)

        user_info = mongoDB_cursor['users'].find_one(
            {"user_id": token_info['user_id']})

        if user_info['verified'] == True:
            return make_response(jsonify({"message": "Email has already been verified"}), 400)

        mongoDB_cursor['users'].update_one({"user_id": token_info['user_id']}, {
            "$set": {"verified": True}})
        mongoDB_cursor['tokens'].delete_one(
            {"token": token, "scope": "verify_email"})

        flash = "Email has been verified successfully, you can now login"
        return make_response(redirect(url_for('routes.sign_in')), 302)

    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Invalid Request, please try again"}), 400)


@routes.route('/account')
def account():
    session = get_session(request)
    if session is None or not session.is_authenticated():
        return redirect(url_for('routes.sign_in'), 302)

    user_info = mongoDB_cursor['users'].find_one({"user_id": session.user_id})
    sessions = get_active_sessions(session.user_id)
    if user_info is None or sessions == []:
        response = make_response(redirect(url_for('routes.sign_in')), 302)
        response.set_cookie('X-Identity', '', httponly=True,
                            secure=True, samesite='Lax', expires=0)
        return response
    return make_response(render_template('account.html', user_info=user_info, sessions=sessions, session_id=session.session_id), 200)


@routes.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return make_response(redirect(url_for('routes.index')), 302)
    try:
        if request.method == 'POST':
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
                if user_info['verified'] == True:
                    return make_response(jsonify({"message": "This email has already been verified"}), 400)
                if user_info['status'] == 'suspended':
                    return make_response(jsonify({"message": "Account is suspended, please contact support"}), 400)
                mongoDB_cursor['tokens'].delete_many(
                    {"user_id": user_info['user_id'], "scope": "verify_email"})
                token = generate_token(user_info, 'verify_email')
                if not send_mail(user_info, token, 'verify_email'):
                    return make_response(jsonify({"message": "Unable to send email, please try again later"}), 500)
                flash("Verification email has been sent successfully")
                return make_response(jsonify({"message": "Verification email has been sent successfully"}), 200)
            else:
                return make_response(jsonify({"message": "Recaptcha is invalid, please try again"}), 400)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Invalid Request, please try again"}), 400)
    return make_response(render_template('resend_verification.html'), 200)


@routes.route('/api/remove_session', methods=['POST'])
def remove_session():
    session = get_session(request)
    if session is None or not session.is_authenticated():
        return make_response(jsonify({"message": "You are not authenticated"}), 401)
    try:
        request_data = request.get_json()
        logout_token = request_data['logout_token']
        if logout_token is None:
            return make_response(jsonify({"message": "Logout token is missing"}), 400)
        Serializer = URLSafeSerializer(config.secret_key)
        logout_token = Serializer.loads(logout_token)
        redis_client.delete(logout_token)
        return make_response(jsonify({"message": "Session has been removed successfully"}), 200)
    except Exception as e:
        return make_response(jsonify({"message": "Invalid Request, please try again"}), 400)


@routes.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'), 302)
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
        if user_info['verified'] == False:
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


@routes.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        request_data = request.get_json()
        token = request_data['token']
        password = request_data['password']

        if token is None or password is None:
            return make_response(jsonify({"message": "Token / Password is missing"}), 400)
        if not verify_recaptcha(request_data['recaptcha_response']):
            return make_response(jsonify({"message": "Recaptcha is invalid, please try again"}), 400)
        Serializer = URLSafeSerializer(config.secret_key)
        token = Serializer.loads(token)
        print(token)

        token_info = mongoDB_cursor['tokens'].find_one(
            {"token": token, "scope": "reset_password"})
        print(token_info)
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
        if user_info['verified'] == False:
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
    return make_response(render_template('reset_password.html', token=token), 200)
