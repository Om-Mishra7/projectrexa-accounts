from app.database import create_redis_database_connection, create_mongoDB_database_connection
from app.config import get_config
from app.functions import hash_password, verify_hashed_password, verify_recaptcha, generate_session, get_session, generate_user_id
from flask import request, jsonify, make_response, Blueprint, render_template, redirect, url_for
import secrets
import requests
import datetime
from itsdangerous import URLSafeSerializer, BadSignature

config = get_config()

serializer = URLSafeSerializer(config.secret_key)

session = {"logged_in": True, "username": "Om Mishra"}

redis_client, mongoDB_client = create_redis_database_connection(
), create_mongoDB_database_connection()

mongoDB_cursor = mongoDB_client['starry_night']

routes = Blueprint('routes', __name__)


@routes.route('/')
def index():
    session = get_session(request)
    if session is None:
        return redirect(url_for('routes.sign_in'))

    try:
        try:
            session_id = serializer.loads(request.cookies.get('X-Identity'))
        except BadSignature:
            return redirect(url_for('routes.sign_in'))
        session_info = mongoDB_cursor['sessions'].find_one(
            {"session_id": session_id})
        return make_response(({"user_info": session, "session_info": {"ip_address": session_info['user_ip_address'], "user_agent": session_info['user_agent'], "country": session_info['country'], "city": session_info['city'], "region": session_info['regionName']}}), 200)
    except Exception as e:
        print(e)
        return make_response(jsonify({"error": e}), 400)


@routes.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    if get_session(request) is not None:
        return redirect(url_for('routes.index'))
    if request.method == 'POST':

        # Initial login checks
        try:
            email = request.form.get('email')
            password = request.form.get('password')

            if email is None or password is None:
                return make_response(jsonify({"message": "Email or Password is missing"}), 400)

            if config.recaptcha:
                recaptcha_response = request.form.get('g-recaptcha-response')

                if recaptcha_response is None:
                    return make_response(jsonify({"message": "Recaptcha is missing"}), 400)

                if not verify_recaptcha(recaptcha_response):
                    return make_response(jsonify({"message": "Recaptcha is invalid"}), 400)
        except:
            return make_response(jsonify({"message": "Invalid Request"}), 400)

        # Database checks
        user = mongoDB_cursor['users'].find_one({"email": email})

        if user is None or user['method'] != 'email':
            return make_response(jsonify({"message": "User does not exist"}), 400)

        if verify_hashed_password(password, user['password']):
            response = make_response(
                jsonify({"message": "{} logged in successfully".format(user['email'])}), 200)
            response.set_cookie('X-Identity', generate_session(user, request), httponly=True, secure=True, samesite='Lax',
                                expires=datetime.datetime.utcnow() + datetime.timedelta(days=30), domain=config.authority)
            return response

        else:
            return make_response(jsonify({"message": "Password is incorrect"}), 400)

    return make_response(render_template('sign_in.html'), 200)


@routes.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if get_session(request) is not None:
        return redirect(url_for('routes.index'))
    if request.method == 'POST':

        email = request.form.get('email')
        password = request.form.get('password')

        if email is None or password is None:
            return make_response(jsonify({"message": "Email or Password is missing"}), 400)

        if mongoDB_cursor['users'].find_one({"email": email}) is not None:
            return make_response(jsonify({"message": "Email already exists"}), 400)

        password, salt = hash_password(password)

        mongoDB_cursor['users'].insert_one(
            {"email": email, "password": password, "salt": salt})
        return make_response(jsonify({"message": "User created successfully"}), 200)

    return make_response(render_template('sign_up.html'), 200)


@routes.route('/oauth/github')
def github_oauth():
    if get_session(request) is not None:
        return redirect(url_for('routes.index'))
    state = secrets.token_hex(32)
    redis_client.set('github_oauth_state', state)
    return make_response(redirect('https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope=user:email'.format(config.github_client_id, config.github_redirect_uri, state))), 302


@routes.route('/callback/github')
def github_callback():
    if get_session(request) is not None:
        return redirect(url_for('routes.index'))
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        if state != redis_client.get('github_oauth_state'):
            return make_response(jsonify({"message": "Invalid state"}), 400)
        response = requests.post('https://github.com/login/oauth/access_token?client_id={}&client_secret={}&code={}&redirect_uri={}'.format(
            config.github_client_id, config.github_client_secret, code, config.github_redirect_uri), headers={'Accept': 'application/json'})

        user_data = requests.get('https://api.github.com/user', headers={
                                 'Authorization': 'Bearer {}'.format(response.json()['access_token'])})

        user_private = mongoDB_cursor['users'].find_one(
            {"email": user_data.json()['email']})

        if user_private is None:
            mongoDB_cursor['users'].insert_one({"id": generate_user_id(), "email": user_data.json()['email'], "password": None, "salt": None, "method": "github", "name": user_data.json()[
                                               'name'], "profile_picture": user_data.json()['avatar_url'], "role": "user", "last_login": datetime.datetime.utcnow(), "created_at": datetime.datetime.utcnow(), "status": "active"})
            user_private = mongoDB_cursor['users'].find_one(
                {"email": user_data.json()['email']})
        else:
            print("Private user data exists", user_private)
            if user_private['method'] != 'github':
                return make_response(jsonify({"message": "This email is already registered with another method"}), 400)

            mongoDB_cursor['users'].update_one({"email": user_private['email']}, {
                                               "$set": {"last_login": datetime.datetime.utcnow()}})

        response = make_response((redirect(url_for('routes.index'))), 302)
        response.set_cookie(
            'X-Identity', generate_session(user_private, request), httponly=True, secure=True, samesite='Lax', expires=datetime.datetime.utcnow() + datetime.timedelta(days=30), domain=config.authority)
        return response

    except Exception as e:
        print(e)
        return make_response(jsonify({"message": "Invalid Request"}), 400)
