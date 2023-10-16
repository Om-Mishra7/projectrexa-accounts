'''
This file contains all the functions used in the application
'''
import time
import datetime
import json
import secrets
import bcrypt
import requests
import redis
import pymongo
from itsdangerous import URLSafeSerializer
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from flask import render_template
from app.config import get_config


config = get_config()


def create_redis_database_connection(max_attempts=10, base_delay=5, attempt_number=1):
    """
     Creates a connection to the Redis database. 
     
     @param max_attempts - Maximum number of attempts to connect to the database
     @param base_delay - Base delay between attempts in seconds.
     @param attempt_number - Number of times we've tried to connect before giving up
     
     @return redis. Redis object with ping method set to True on success False on failure ( in which case it will be re - tried
    """
    # Attempts to connect to Redis and return a Redis connection.
    while attempt_number <= max_attempts:

        try:
            redis_client = redis.Redis.from_url(
                config.redis_url, decode_responses=True)
            redis_client.ping()
            return redis_client

        except Exception as e:
            print("Redis Connection Error: ", e)
            time.sleep(base_delay * attempt_number**2)
            create_redis_database_connection(attempt_number=attempt_number+1)


def create_mongoDB_database_connection(max_attempts=10, base_delay=5, attempt_number=1):
    """
     Creates a connection to the MongoDB server.
     
     @param max_attempts - Maximum number of attempts to connect
     @param base_delay - Base delay between attempts in seconds
     @param attempt_number - Number of attempts to connect before giving up
     
     @return MongoClient with server_info () on success None on failure ( in which case it will be retried
    """
    # Attempts to connect to the MongoDB database.
    while attempt_number <= max_attempts:

        try:
            mongo_client = pymongo.MongoClient(config.mongoDB_url)
            mongo_client.server_info()
            return mongo_client

        except Exception as e:
            print("MongoDB Connection Error: ", e)
            time.sleep(base_delay * attempt_number**2)
            create_mongoDB_database_connection(attempt_number=attempt_number+1)


redis_client, mongoDB_client = create_redis_database_connection(
), create_mongoDB_database_connection()

mongoDB_cursor = mongoDB_client['starry_night']

# Sendinblue API Key
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = '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'


class User:
    def __init__(self, session_id, user_id, name, email, profile_picture, role, ip_address, status):
        """
         Initialize the object with the data. This is the constructor for the Session class.
         
         @param session_id - The session id of the user who will be logged in.
         @param user_id - The user's email address.
         @param name - The user's name. This can be any string but it is recommended to use alphanumeric characters as long as the user is not in use by any
         @param email
         @param profile_picture
         @param role
         @param ip_address
         @param status
        """
        self.session_id = session_id
        self.user_id = user_id
        self.name = name
        self.email = email
        self.profile_picture = profile_picture
        self.role = role
        self.ip_address = ip_address
        self.status = status
        self.logged_in = True

    def is_authenticated(self):
        """
         Check if user is authenticated.
         
         
         @return True if logged in and status is active False otherwise. Note that this will return False even if the user is logged in but the status is not active
        """
        # Returns true if the user is logged in and the status is active.
        if self.logged_in and self.user_id is not None and self.status == "active":
            return True
        return False

    def is_admin(self):
        """
         Checks if the user is an admin. Admins are roles that require admin access to the user's data.
         
         
         @return True if the user is an admin False otherwise.
        """
        # if role is admin return true
        if self.role == "admin":
            return True
        return False

    def get_user_info(self, format):
        """
         Returns information about the user in the requested format. This is useful for debugging purposes as it will return a dictionary instead of a User object
         
         @param format - Format to return information in
         
         @return User information in requested format or User object if format is not set to json ( default ). In other
        """
        # JSON representation of this object
        if format == "json":
            return {"user_id": self.user_id, "name": self.name, "email": self.email, "profile_picture": self.profile_picture, "role": self.role, "ip_address": self.ip_address, "status": self.status, "logged_in": self.logged_in}
        return self


def hash_password(password, salt=None):
    """
     Hashes a password with bcrypt. This is useful for passwords that don't need to be hashed in order to get the same password again
     
     @param password - The password to be hashed
     @param salt - The salt to be used for hashing the password
     
     @return The hashed password as a utf - 8 encoded string >>> hash_password ('john')
    """
    # Generate a salt value if not provided
    # Returns the salt of the salt if not set.
    if not salt:
        salt = bcrypt.gensalt().decode('utf-8')

    # Hash the password with the provided salt
    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'), salt.encode('utf-8'))

    return hashed_password.decode('utf-8')


def verify_hashed_password(password, hashed_password):
    """
     Verify a password against a hashed password. This is useful for verifying passwords that have been hashed with other means such as password hashing.
     
     @param password - The password to verify. Must be UTF - 8 encoded.
     @param hashed_password - The plain - text password that was hashed with bcrypt.
     
     @return True if the password is correct False otherwise. Note that the return value is a boolean rather than a string
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def verify_recaptcha(recaptcha_response):
    """
     Verify a recaptcha response. This is a wrapper around the reCAPTCHA API to verify the user's response to a recaptcha challenge.
     
     @param recaptcha_response - The response from the recaptcha challenge.
     
     @return True if the response is correct False otherwise. Example :. from google. test import verify_recaptcha assert verify_recaptcha ( " John Smith "
    """
    payload = {
        'secret': config.recaptcha_secret_key,
        'response': recaptcha_response
    }
    response = requests.post(
        "https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    # Returns true if the response is successful and score is greater than 0. 5
    if response_text['success'] == True and response_text['score'] >= 0.5:
        return True
    return False


def generate_session(user, request):
    """
     Generate a session for the user. This is used to authenticate the user to the Google Apps API
     
     @param user - The user that is logged in
     @param request - The request that was made to the Google Apps API
     
     @return A dictionary containing the session information to be stored in the session_id field of the user's
    """
    serializer = URLSafeSerializer(config.secret_key)
    session_id = secrets.token_hex(16)
    session = {
        'logged_in': True,
        'user_id': user['user_id'],
        'user_name': user['name'],
        'user_email': user['email'],
        'user_role': user['role'],
        'status': user['status'],
        'user_profile_picture': user['profile_picture'],
        'user_ip_address': request.remote_addr,
        'user_agent': request.user_agent.string,
        'session_id': session_id
    }

    location_info = requests.get(
        'http://ip-api.com/json/{}?fields=16409'.format(request.remote_addr)).json()

    # This function is used to set the country region name and city of the location
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
        "user_id": user['user_id'],
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
    """
     Get the session from the request. This is used to check if there is a session and if so return it
     
     @param request - The request that contains the session
     
     @return The session or None if not logged in or no session is in the request's cookie ( which is the case for users that don't have an identity
    """
    # Returns the User object from the session cookie.
    if request.cookies.get('X-Identity') is not None:
        serializer = URLSafeSerializer(config.secret_key)
        try:
            session_id = serializer.loads(request.cookies.get('X-Identity'))
        except Exception as e:
            return None
        try:
            session = json.loads(redis_client.get(session_id))

        except Exception as e:
            return None

        return User(session['session_id'], session['user_id'], session['user_name'], session['user_email'], session['user_profile_picture'], session['user_role'], session['user_ip_address'], session['status'])
    else:
        return None


def generate_user_id():
    """
     Generate a user id. If there is already a user with the same id in the database this function will recurse to generate a new one.
     
     
     @return The generated user id or None if one could not be generated for some reason ( not found or already existing
    """
    user_id = secrets.token_hex(4)
    # Returns the user_id of the user.
    if mongoDB_cursor['users'].find_one({"user_id": user_id}) is not None:
        return generate_user_id()
    return user_id


def generate_token(user, scope):
    """
     Generate a token for the given user and scope. This will delete all tokens with the same scope for the user and add a 6 hours token to the user
     
     @param user - The user to generate a token for
     @param scope - The scope of the token to generate. Must be one of the scopes defined in config.
     
     @return The token as a hex string that can be used as a URL or encoded as a Base64 string
    """
    serializer = URLSafeSerializer(config.secret_key)
    token = secrets.token_hex(32)
    mongoDB_cursor["tokens"].delete_many({"user_id": user['user_id'], "scope": scope}) # Delete all tokens with same scope for the user
    mongoDB_cursor['tokens'].insert_one({
        "token": token,
        "user_id": user['user_id'],
        "created_at": datetime.datetime.now(),
        "expires_at": datetime.datetime.now() + datetime.timedelta(hours=6),
        "scope": scope
    })

    return (serializer.dumps(token))


def get_active_sessions(user_id):
    """
     Get a list of active sessions for a user. This is used to check if there are any active sessions for a user.
     
     @param user_id - The user to check. It must be a member of the Sessions collection.
     
     @return A list of session dictionaries that have been marked as active and are no longer in the session store. The logout token is set to the session ID
    """
    Serializer = URLSafeSerializer(config.secret_key)
    sessions = []
    # Add a session to the session list.
    for session in mongoDB_cursor['sessions'].find({"user_id": user_id}):
        # Add a session to the session list.
        if redis_client.get(session['session_id']) is not None:
            session = {
                **session, **{"logout_token": Serializer.dumps(session['session_id'])}}
            sessions.append(session)
        else:
            mongoDB_cursor['sessions'].delete_one(
                {"session_id": session['session_id']})
    return sessions


def deleter_all_sessions(user_id):
    """
     Deletes all sessions for a user. This is used to clean up after a user has logged out.
     
     @param user_id - The id of the user who's sessions are to be deleted.
     
     @return True if everything went well False otherwise. Note that this will return True even if there are no sessions
    """
    # Delete all sessions that have been deleted from the database.
    for session in mongoDB_cursor['sessions'].find({"user_id": user_id}):
        redis_client.delete(session['session_id'])
        mongoDB_cursor['sessions'].delete_one(
            {"session_id": session['session_id']})
    return True


def send_mail(user, token, type):
    """
     Send email to user. This is used to send password reset email if user forgot password is requested
     
     @param user - dictionary with user data from projectrexa. accounts. projectrexa.
     @param token - token sent to user forgot password
     @param type - type of email to send ( forgot password or reset_password )
     
     @return True if email was sent False if not ( in which case it is not sent ). The return value is a boolean
    """
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration))

    # forgot_password Send email to the user s email.
    if type == "forgot_password":
        subject = "Forgot Password Request | ProjectRexa"
        sender = {"name": "ProjectRexa",
                    "email": "noreply@projectrexa.dedyn.io"}
        to = [{"email": user["email"], "name": user["name"]}]
        reply_to = {"email": "contact@projectrexa.dedyn.io",
                    "name": "ProjectRexa"}
        html = render_template(
            'email/forgot_password.html', name=user['name'], link="https://accounts.projectrexa.dedyn.io/reset-password?token={}".format(token))
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            to=to, html_content=html, reply_to=reply_to, sender=sender, subject=subject)

    # Verify Email or ProjectRexa. Returns True if the email was verified successfully.
    if type == "verify_email":
        subject = "Verify Email | ProjectRexa"
        sender = {"name": "ProjectRexa",
                    "email": "noreply@projectrexa.dedyn.io"}
        to = [{"email": user["email"], "name": user["name"]}]
        reply_to = {"email": "contact@projectrexa.dedyn.io",
                    "name": "ProjectRexa"}
        html = render_template(
            'email/verify_email.html', name=user['name'], link="https://accounts.projectrexa.dedyn.io/verify-email?token={}".format(token))
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            to=to, html_content=html, reply_to=reply_to, sender=sender, subject=subject)

    else:
        return False
    try:
        api_instance.send_transac_email(send_smtp_email)
        return True
    except ApiException:
        return False
