from app.config import get_config
from app.database import create_redis_database_connection, create_mongoDB_database_connection
import bcrypt
import requests
import json
import secrets
from itsdangerous import URLSafeSerializer
import datetime
from flask import make_response, redirect, url_for

config = get_config()

redis_client, mongoDB_client = create_redis_database_connection(
), create_mongoDB_database_connection()

mongoDB_cursor = mongoDB_client['starry_night']


class User:
    def __init__(self, id, name, email, profile_picture, role, ip_address, status):
        self.id = id
        self.name = name
        self.email = email
        self.profile_picture = profile_picture
        self.role = role
        self.ip_address = ip_address
        self.status = status
        self.logged_in = True

    def is_authenticated(self):
        if self.logged_in and self.id is not None and self.status == "active":
            return True
        return False
    
    def is_admin(self):
        if self.role == "admin":
            return True
        return False
    
    def get_user_info(self,format):
        if format == "json":
            return {"id": self.id, "name": self.name, "email": self.email, "profile_picture": self.profile_picture, "role": self.role, "ip_address": self.ip_address, "status": self.status, "logged_in": self.logged_in}
        return self


def hash_password(password, salt=None):
    # Generate a salt value if not provided
    if not salt:
        salt = bcrypt.gensalt().decode('utf-8')

    # Hash the password with the provided salt
    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'), salt.encode('utf-8'))

    return hashed_password.decode('utf-8'), salt


def verify_hashed_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def verify_recaptcha(recaptcha_response):
    payload = {
        'secret': config.recaptcha_secret_key,
        'response': recaptcha_response
    }
    response = requests.post(
        "https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    if response_text['success'] == "true":
        return True
    return False


def generate_session(user, request):
    serializer = URLSafeSerializer(config.secret_key)
    session = {
        'logged_in': True,
        'user_id': user['id'],
        'user_name': user['name'],
        'user_email': user['email'],
        'user_role': user['role'],
        'status': user['status'],
        'user_profile_picture': user['profile_picture'],
        'user_ip_address': request.remote_addr,
        'user_agent': request.user_agent.string,

    }

    session_id = secrets.token_hex(16)

    location_info = requests.get(
        'http://ip-api.com/json/{}?fields=16409'.format(request.remote_addr)).json()

    if location_info['status'] == 'fail':
        country = "Unknown"
        regionName = "Unknown"
        city = "Unknown"
    else:
        country = location_info['country']
        regionName = location_info['regionName']
        city = location_info['city']

    mongoDB_cursor['sessions'].insert_one({
        "session_id": session_id,
        "user_id": user['id'],
        "user_ip_address": request.remote_addr,
        "user_agent": request.user_agent.string,
        "created_at": datetime.datetime.now(),
        "country": country,
        "regionName": regionName,
        "city": city
    })

    redis_client.set(session_id, json.dumps(session), ex=2630000)

    return (serializer.dumps(session_id))


def get_session(request):
    if request.cookies.get('X-Identity') is not None:
        serializer = URLSafeSerializer(config.secret_key)
        try:
            session_id = serializer.loads(request.cookies.get('X-Identity'))
        except Exception as e:
            with open('log.log', 'a') as f:
                f.write('{} | ERROR | {}\n\n'.format(
                    datetime.datetime.now(), e))
            return None
        try:
            session = json.loads(redis_client.get(session_id))
            if session['user_ip_address'] != request.remote_addr:
                return None
                
        except Exception as e:
            with open('log.log', 'a') as f:
                f.write('{} | ERROR | {}\n\n'.format(
                    datetime.datetime.now(), e))
            return None
        
        return User(session['user_id'], session['user_name'], session['user_email'], session['user_profile_picture'], session['user_role'], session['user_ip_address'], session['status'])
    else:
        return None


def generate_user_id():
    user_id = secrets.token_hex(16)
    if mongoDB_cursor['users'].find_one({"id": user_id}) is not None:
        return generate_user_id()
    return user_id