from app.database import create_redis_database_connection, create_mongoDB_database_connection
from app.config import get_config
from app.functions import hash_password, verify_hashed_password, verify_recaptcha, generate_session, get_session, generate_user_id, generate_token, send_mail
from flask import request, jsonify, make_response, Blueprint, render_template, redirect, url_for, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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
        session_info = mongoDB_cursor['sessions'].find_one(
            {"session_id": session_id})
        return make_response(({"user_info": session.get_user_info("json"), "session_info": {"ip_address": session_info['user_ip_address'], "user_agent": session_info['user_agent'], "country": session_info['country'], "city": session_info['city'], "region": session_info['regionName']}}), 200)
    except Exception as e:
        return (jsonify({"error": e}), 400)


@routes.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'), 302)
    if request.method == 'POST':

        # Initial login checks
        try:
            request_data = request.get_json()
            email = request_data['email']
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
        except:
            return make_response(jsonify({"message": "We are experiencing some issues, please try again later"}), 500)

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

    return make_response(render_template('sign_in.html'), 200)


@routes.route('/sign-up', methods=['GET', 'POST'])
def signup():
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'), 302)
    if request.method == 'POST':

        email = request.form.get('email')
        password = request.form.get('password')

        if email is None or password is None:
            return make_response(jsonify({"message": "Email or Password is missing"}), 400)

        if mongoDB_cursor['users'].find_one({"email": email}) is not None:
            return make_response(jsonify({"message": "Email already exists"}), 400)

        mongoDB_cursor['users'].insert_one(
            {"email": email, "password": hash_password(password),"method": "email", "user_id": generate_user_id(), "verified": False, "name": "User", "role": "user", "status": "active", "created_at": datetime.datetime.utcnow(), "last_login": datetime.datetime.utcnow()})
        return make_response(jsonify({"message": "User created successfully"}), 200)

    return make_response(render_template('sign_up.html'), 200)


@routes.route('/sign-out')
def signout():
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
    redis_client.set(secret_cookie, state, ex=30)
    response = make_response(redirect('https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope=user:email'.format(
        config.github_client_id, config.github_redirect_uri, state)))
    response.set_cookie('X-GitHub-State', secret_cookie, httponly=True, secure=True,
                        samesite='Lax', expires=datetime.datetime.utcnow() + datetime.timedelta(seconds=90))
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
                return make_response(jsonify({"message": "Invalid state"}), 400)

            redis_client.delete(request.cookies.get('X-GitHub-State'))

        except Exception as e:
            return make_response(jsonify({"message": "Invalid state"}), 400)

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
        print(user_data)
        user_private = mongoDB_cursor['users'].find_one(
            {"email": user_data['email']})

        if user_private is None:
            mongoDB_cursor['users'].insert_one({"id": generate_user_id(), "email": user_data['email'], "password": None, "salt": None, "method": "github", "name": user_data[
                                               'name'], "profile_picture": user_data['avatar_url'], "role": "user", "last_login": datetime.datetime.utcnow(), "created_at": datetime.datetime.utcnow(), "status": "active"})
            user_private = mongoDB_cursor['users'].find_one(
                {"email": user_data['email']})
        else:
            if user_private['method'] != 'github':
                return make_response(jsonify({"message": "This email is already registered with another method"}), 400)

            mongoDB_cursor['users'].update_one({"email": user_private['email']}, {
                                               "$set": {"last_login": datetime.datetime.utcnow()}})

        response = make_response((redirect(url_for('routes.index'))), 302)
        response.set_cookie(
            'X-Identity', generate_session(user_private, request), httponly=True, secure=True, samesite='Lax', expires=datetime.datetime.utcnow() + datetime.timedelta(days=30), domain=config.authority)
        return response

    except Exception as e:
        return make_response(jsonify({"message": "Invalid Request"}), 400)


@routes.route('/oauth/google')
def google_oauth():
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'))
    return jsonify("Coming Soon")


@routes.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'))
    if request.method == 'POST':
        email = request.form.get('email')
        if email is None:
            return make_response(jsonify({"message": "Email is missing"}), 400)
        user = mongoDB_cursor['users'].find_one({"email": email})
        if user is None:
            return make_response(jsonify({"message": "If we find an account associated with this email, we will send you a link to reset your password"}), 200)
        if user['method'] != 'email':
            return make_response(jsonify({"message": "This email is registered with another method"}), 400)
        token = generate_token(user)
        if not send_mail(user, token, 'forgot_password'):
            return make_response(jsonify({"message": "We are unable to send you an email at this time. Please try again later"}), 500)
        return make_response(jsonify({"message": "If we find an account associated with this email, we will send you a link to reset your password"}), 200)
    return make_response(render_template('forgot_password.html'), 200)


@routes.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    serializer = URLSafeSerializer(config.secret_key)
    session = get_session(request)
    if session is not None and session.is_authenticated():
        return redirect(url_for('routes.index'))
    """ if request.method == 'POST':
        token = request.form.get('token')
        password = request.form.get('password')
        if token is None or password is None:
            return make_response(jsonify({"message": "Token or Password is missing"}), 400)
        try:
            user = verify_token(token)
        except Exception as e:
            return make_response(jsonify({"message": "Invalid Token"}), 400)
        mongoDB_cursor['users'].update_one({"email": user['email']}, {
                                           "$set": {"password": hash_password(password, user['salt'])}})
        return make_response(jsonify({"message": "Password reset successfully"}), 200) """
    token = request.args.get('token')
    if token is None:
        return make_response(jsonify({"message": "Token is missing"}), 400)
    try:
        serializer = URLSafeSerializer(config.secret_key)
        token = serializer.loads(token)
        if mongoDB_cursor['tokens'].find_one({"token": token}) is None:
            print("Token not found")
            return make_response(jsonify({"message": "Invalid Token"}), 400)

        mongoDB_cursor['tokens'].delete_one({"token": token})
        return make_response(jsonify({"message": "Token is valid"}), 200)
    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Invalid Token"}), 400)


@routes.route('/change-password', methods=['GET', 'POST'])
def change_password():
    session = get_session(request)
    if session is None or not session.is_authenticated():
        return redirect(url_for('routes.login'))
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        if old_password is None or new_password is None:
            return make_response(jsonify({"message": "Old Password or New Password is missing"}), 400)
        user = mongoDB_cursor['users'].find_one({"id": session.user_id})
        if user is None:
            return make_response(jsonify({"message": "User not found"}), 400)
        if user['method'] != 'email':
            return make_response(jsonify({"message": "This email is registered with another method"}), 400)
        if not verify_hashed_password(old_password, user['password'], user['salt']):
            return make_response(jsonify({"message": "Incorrect Password"}), 400)
        mongoDB_cursor['users'].update_one({"id": user['id']}, {
                                           "$set": {"password": hash_password(new_password)}})
        return make_response(jsonify({"message": "Password changed successfully"}), 200)
    return make_response(render_template('change_password.html'), 200)


@routes.route('/user/<user_id>')
def user(user_id):
    session = get_session(request)
    if session is None or not session.is_authenticated():
        return redirect(url_for('routes.login'))
    if user_id == session.user_id:
        return redirect(url_for('routes.index'))
    user = mongoDB_cursor['users'].find_one({"id": user_id})
    if user is None:
        return make_response(jsonify({"message": "User not found"}), 400)
    return make_response(render_template('user.html', user=user), 200)


@routes.route('/ping')
def ping():
    return make_response(jsonify({"message": "pong"}), 200)
