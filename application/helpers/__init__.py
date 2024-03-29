import json
import bcrypt
import resend
import secrets
import requests
import datetime
from application.config import Config

Config = Config()

def resolve_ip_address_to_country(ip_address):
    '''
    Resolve the IP address to the country name

    :param ip_address: The IP address of the user
    :return: The country name of the user
    '''
    try:
        ip_api_response = requests.get(f"https://freeipapi.com/api/json/{ip_address}", timeout=1)
        print(ip_api_response.json())
        if ip_api_response.status_code == 200:
            return ip_api_response.json()['countryName']
        return 'Unknown'
    except:
        return 'Unknown'

def generate_guest_session(request, redis_connection):
    '''
    Generate a guest session for the user

    :param request: The request object from the view
    :param redis_connection: The connection object to the redis server
    :return: A dictionary containing the user information
    '''

    session = {
        'session_id': secrets.token_urlsafe(128),
        'session_info': {
            'session_type': 'guest',
            'session_csrf_token': secrets.token_urlsafe(32),
            'session_creation_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'session_last_access_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'session_ip_address': request.remote_addr,
            'session_user_agent': request.headers.get('User-Agent'),
            'session_referer': request.headers.get('Referer'),
            'session_country': resolve_ip_address_to_country(request.remote_addr),
        },
        'user_info': None    
    }


    redis_connection.set(session['session_id'], json.dumps(session))
    return session

def generate_user_session(user_info, request, redis_connection, database_connection):
    '''
    Generate a user session for the user

    :param user_info: The information of the user
    :param request: The request object from the view
    :param redis_connection: The connection object to the redis server
    :param database_connection: The connection object to the database
    :return: A dictionary containing the user information
    '''
    session = {
        'session_id': secrets.token_urlsafe(128),
        'session_info': {
            'session_type': 'user',
            'session_csrf_token': secrets.token_urlsafe(32),
            'session_creation_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'session_last_access_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'session_ip_address': request.remote_addr,
            'session_user_agent': request.headers.get('User-Agent'),
            'session_referer': request.headers.get('Referer'),
            'session_country': resolve_ip_address_to_country(request.remote_addr),
        },
        'user_info': {
            'user_public_id': user_info['user_public_id'],
            'user_name': user_info['user_name'],
            'user_role': user_info['user_profile_info']['user_role'],
            'user_full_name': user_info['user_profile_info']['user_full_name'],
            'user_email': user_info['user_email'],
        }
    }

    redis_connection.set(session['session_id'], json.dumps(session))

    database_connection['users'].update_one({'user_public_id': user_info['user_public_id']}, {'$set': {'user_account_info.user_account_last_login_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'user_account_info.user_account_last_login_ip': request.remote_addr}})

    database_connection['sessions'].insert_one({
        'session_id': session['session_id'],
        'session_user_id': user_info['user_public_id'],
        'session_creation_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'session_ip_address': request.remote_addr,
        'session_user_agent': request.headers.get('User-Agent'),
        'session_referer': request.headers.get('Referer'),
        'session_country': request.headers.get('CF-IPCountry'),
    })

    return session

def load_cookie_session(request, redis_connection, session_id):
    '''
    Load the user session from the session cookie

    :param request: The request object from the view
    :param redis_connection: The connection object to the redis server
    :param session_cookie: The session cookie from the request
    :return: A dictionary containing the user information
    '''
    session= redis_connection.get(session_id)
    if session is None:
        return generate_guest_session(request, redis_connection)
    else:
        session = json.loads(session)
    if datetime.datetime.strptime(session['session_info']['session_last_access_time'], '%Y-%m-%d %H:%M:%S') < datetime.datetime.now() - datetime.timedelta(days=180):
        redis_connection.delete(session['session_id'])
        return generate_guest_session(request, redis_connection)
    if session['session_info']['session_user_agent'] != request.headers.get('User-Agent'):
        redis_connection.delete(session['session_id'])
        return generate_guest_session(request, redis_connection)
    update_session_access_time(session, redis_connection)
    return session

def update_session_access_time(session, redis_connection):
    '''
    Update the last access time of the session

    :param session: The session object
    :param redis_connection: The connection object to the redis server
    '''
    session['session_info']['session_last_access_time'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    redis_connection.set(session['session_id'], json.dumps(session))
    return session

def generate_user_public_id(database_connection):
    '''
    Generate a unique public id for the user

    :param database_connection: The connection object to the database
    :return: A unique public id
    '''
    public_id = str(secrets.token_urlsafe(16)).replace('-', '').replace('_', '')
    if database_connection['users'].find_one({'user_public_id': public_id}) is not None:
        return generate_user_public_id(database_connection)
    return public_id

def generate_user_name(user_name, database_connection):
    '''
    Generate a unique username for the user

    :param user_name: The name of the user
    :param database_connection: The connection object to the database
    :return: A unique username
    '''
    user_name = user_name.replace(' ', '_').lower().strip()
    if database_connection['users'].find_one({'user_name': user_name}) is not None:
        return generate_user_name(user_name + '_' + str(secrets.token_urlsafe(4)), database_connection)
    return user_name

def generate_hashed_password(password):
    '''
    Generate a hashed password for the user

    :param password: The password of the user
    :return: A hashed password
    '''
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def verify_hashed_password(password, hashed_password):
    '''
    Verify the hashed password for the user

    :param password: The password of the user
    :param hashed_password: The hashed password of the user
    :return: A boolean value indicating if the password is correct
    '''
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)

def generate_token(token_type, user_id, database_connection):
    '''
    Generate a unique token for the user

    :param token_type: The type of the token
    :param user_id: The id of the user
    :param database_connection: The connection object to the database
    :return: A unique token
    '''
    while True:
        token = str(secrets.token_urlsafe(64))
        if database_connection['tokens'].find_one({'token': token}) is None:
            break                                   
    database_connection['tokens'].delete_many({'token_user_id': user_id, 'token_type': token_type})
    token_info = {
        'token': token,
        'token_type': token_type,
        'token_user_public_id': user_id,
        'token_created_at': datetime.datetime.now()
    }
    database_connection['tokens'].insert_one(token_info)
    return token

def send_email_verification_email(user_email, user_full_name, token):
    '''
    Send an email verification email to the user

    :param user_email: The email of the user
    :param user_full_name: The full name of the user
    :param token: The token for the email verification
    '''
    send_email(user_email, user_full_name, 'Email Verification | ProjectRexa', f"""
               <body><div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px"><p style="font-size:16px">Hello {user_full_name.title()} 👋,</p><p style="font-size:16px">Thank you for signing up! To get started, please verify your email address by clicking the link below:</p><p style="font-size:16px"><a href="https://accounts.om-mishra.com/auth/email/verification/verify?verification_token={token}" style="color:#007bff;text-decoration:none">https://accounts.om-mishra.com/auth/email/verification/verify?verification_token={token}</a></p><p style="font-size:16px">If you have any questions or need assistance, feel free to reach out to our support team at <a href="mailto:support@om-mishra.com" style="color:#007bff;text-decoration:none">support@om-mishra.com</a>.</p><p style="font-size:16px">Best Regards,<br>The Team at ProjectRexa</p></div></body>""")             

def send_password_reset_email(user_email, user_full_name, token):
    '''
    Send a password reset email to the user

    :param user_email: The email of the user
    :param user_full_name: The full name of the user
    :param token: The token for the password reset
    '''
    send_email(user_email, user_full_name, 'Password Reset | ProjectRexa', f"""
               <body><div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px"><p style="font-size:16px">Hello {user_full_name.title()},</p><p style="font-size:16px">We received a request to reset your password. To reset your password, please click the link below:</p><p style="font-size:16px"><a href="https://accounts.om-mishra.com/auth/password/reset-password?reset_token={token}" style="color:#007bff;text-decoration:none">https://accounts.om-mishra.com/auth/password/reset-password?reset_token={token}</a></p><p style="font-size:16px">If you did not request a password reset, please ignore this email. If you have any questions or need assistance, feel free to reach out to our support team at <a href="mailto:support@om-mishra.com" style="color:#007bff;text-decoration:none">support@om-mishra.com</a>.</p><p style="font-size:16px">Best Regards,<br>The Team at ProjectRexa</p></div></body>""")

def send_email(user_email, user_full_name, subject, body):
    '''
    Send an email to the user

    :param user_email: The email of the user
    :param user_full_name: The full name of the user
    :param subject: The subject of the email
    :param message: The message of the email
    '''
    resend.api_key = Config.resend_api_key

    try:

        resend.Emails.send({
            "from": "Accounts ProjectRexa <accounts@om-mishra.com>",
            "to": f"{user_full_name.title()} <{user_email}>",
            "reply_to": "contact@om-mishra.com",
            "subject": subject,
            "html": body
        })

        return True
    
    except Exception as e:
        return False

def verifiy_csrf_token(request, global_context):
    '''
    Verify the CSRF token for the user

    :param request: The request object from the view
    :param global_context: The global context object
    :return: A boolean value indicating if the CSRF token is valid
    '''
    print(request.args)
    csrf_token = request.args.get('csrf_token')
    print(csrf_token)
    if csrf_token is None or csrf_token != global_context.session['session_info']['session_csrf_token']:
        return False
    return True

def filter_valid_sessions(user_sessions, redis_connection):
    '''
    Filter the valid sessions for the user

    :param user_sessions: The sessions of the user
    :param redis_connection: The connection object to the redis server
    :return: A list of valid sessions
    '''
    valid_sessions = []
    for session in user_sessions:
        session = json.loads(redis_connection.get(session['session_id']))
        if session is not None and datetime.datetime.strptime(session['session_info']['session_last_access_time'], '%Y-%m-%d %H:%M:%S') > datetime.datetime.now() - datetime.timedelta(days=180):
            valid_sessions.append(session)
        else:
            redis_connection.delete(session['session_id'])
    return valid_sessions