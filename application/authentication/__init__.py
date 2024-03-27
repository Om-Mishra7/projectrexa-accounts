import datetime
from flask import jsonify
from application.helpers import generate_user_public_id, generate_user_name, generate_hashed_password, generate_token , send_email_verification_email, verify_hashed_password, generate_user_session, generate_guest_session

def handle_email_signup(request, database_connection):
    
    try:
        request_data = request.get_json()
    except:
        request_data = None

    if request_data is None:
        return jsonify({'status': 'error', 'message': 'The request data is invalid'}), 400
    
    user_name = request_data.get('name').strip().title()
    user_email = request_data.get('email').strip().lower().replace(' ', '')
    user_password = request_data.get('password').strip()


    if database_connection['users'].find_one({'user_email': user_email}) is not None:
        return jsonify({'status': 'error', 'message': 'An account with this email address already exists, please login'}), 400
    
    
    
    user_data = {
        'user_public_id': generate_user_public_id(database_connection),
        'user_name': generate_user_name(user_name, database_connection),
        'user_email': user_email,
        'user_hashed_password': generate_hashed_password(user_password),
        'user_profile_info': {
            'user_role': 'user',
            'user_full_name': user_name,
            'user_profile_picture': 'https://ui-avatars.com/api/?format=svg?name=' + user_name,
        },
        'user_account_info': {
            'user_account_type': 'email',
            'user_account_status': 'active',
            'user_account_verification_status': 'pending',
            'user_account_created_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'user_account_last_login_at': None,
            'user_account_last_login_ip': None,
        },
    }

    database_connection['users'].insert_one(user_data)

    email_verification_token = generate_token('email_verification', user_data['user_public_id'], database_connection)

    send_email_verification_email(user_email, user_data['user_profile_info']['user_full_name'], email_verification_token)

    return jsonify({'status': 'success', 'message': 'The account has been created successfully, please verify your email address'}), 201
    
def handle_email_signin(request, database_connection, redis_connection, global_context):
    
    try:
        request_data = request.get_json()
    except:
        request_data = None

    if request_data is None:
        return jsonify({'status': 'error', 'message': 'The request data is invalid'}), 400
    
    user_email = request_data.get('email').strip().lower().replace(' ', '')
    user_password = request_data.get('password').strip()

    user_data = database_connection['users'].find_one({'user_email': user_email})

    if user_data is None:
        return jsonify({'status': 'error', 'message': 'No account associated with this email address exists, please sign up'}), 400
    
    if user_data['user_account_info']['user_account_type'] != 'email':
        return jsonify({'status': 'error', 'message': 'The account is not an email account, please use the appropriate login method'}), 400
    
    if user_data['user_account_info']['user_account_verification_status'] == 'pending':
        return jsonify({'status': 'error', 'message': 'The account is not verified, please check your inbox or request another&nbsp;<a href="/auth/email/verification/resend">verification email.</a>'}), 400
    
    if user_data['user_account_info']['user_account_status'] == 'suspended':
        return jsonify({'status': 'error', 'message': 'The account is suspended, please contact the support team'}), 400
    
    if user_data['user_account_info']['user_account_status'] == 'deleted':
        return jsonify({'status': 'error', 'message': 'The account is deleted, please contact the support team'}), 400
    
    if not verify_hashed_password(user_password, user_data['user_hashed_password']):
        return jsonify({'status': 'error', 'message': 'The password is incorrect, please try again or&nbsp;<a href="/auth/password/reset">reset your password.</a>'}), 400
    
    global_context.session = generate_user_session(user_data, request, redis_connection, database_connection)

    return jsonify({'status': 'success', 'message': 'The account has been logged in successfully', 'session_id': global_context.session['session_id']}), 200

def handle_user_signout(request, redis_connection, database_connection, global_context):
    
    redis_connection.delete(global_context.session['session_id'])
    database_connection['sessions'].delete_one({'session_id': global_context.session['session_id']})
    global_context.session = generate_guest_session(request, redis_connection)

    return jsonify({'status': 'success', 'message': 'The account has been logged out successfully'}), 200