import datetime
from flask import jsonify, redirect
from application.helpers import generate_user_public_id, generate_user_name, generate_hashed_password, generate_token , send_email_verification_email, verify_hashed_password, generate_user_session, generate_guest_session, verifiy_csrf_token, send_password_reset_email

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
            'user_profile_picture': 'https://ui-avatars.com/api/?format=svg&name=' + user_name,
        },
        'user_account_info': {
            'user_account_type': 'email',
            'user_account_status': 'active',
            'user_account_verification_status': 'pending',
            'user_account_created_at': datetime.datetime.now(),
            'user_account_last_login_at': None,
            'user_account_last_login_ip': None,
            'user_password_last_updated_at': datetime.datetime.now(),
        },
    }

    database_connection['users'].insert_one(user_data)

    email_verification_token = generate_token('email_verification', user_data['user_public_id'], database_connection)

    send_email_verification_email(user_email, user_data['user_profile_info']['user_full_name'], email_verification_token)

    return jsonify({'status': 'success', 'message': 'The account has been created successfully, please check your inbox for the verification email'}), 200
    
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
        return jsonify({'status': 'error', 'message': f'The account is not verified, please check your inbox or request another&nbsp;<a href="/auth/email/verification/resend?idenifier={user_data["user_public_id"]}&csrf_token={global_context.session["session_info"]["session_csrf_token"]}">verification email</a>'}), 400
    
    if user_data['user_account_info']['user_account_status'] == 'suspended':
        return jsonify({'status': 'error', 'message': 'The account is suspended, please contact the support team'}), 400
    
    if user_data['user_account_info']['user_account_status'] == 'deleted':
        return jsonify({'status': 'error', 'message': 'The account is deleted, please contact the support team'}), 400
    
    if not verify_hashed_password(user_password, user_data['user_hashed_password']):
        return jsonify({'status': 'error', 'message': f'The password is incorrect, please try again or&nbsp;<a href="/auth/password/forgot-password?idenifier={user_data["user_public_id"]}&csrf_token={global_context.session["session_info"]["session_csrf_token"]}">reset the password</a>'}), 400
                        
    global_context.session = generate_user_session(user_data, request, redis_connection, database_connection)

    return jsonify({'status': 'success', 'message': 'The account has been logged in successfully', 'session_id': global_context.session['session_id']}), 200

def handle_user_signout(request, redis_connection, database_connection, global_context):
    
    redis_connection.delete(global_context.session['session_id'])
    database_connection['sessions'].delete_one({'session_id': global_context.session['session_id']})
    global_context.session = generate_guest_session(request, redis_connection)

    return jsonify({'status': 'success', 'message': 'The account has been logged out successfully'}), 200

def handle_email_verification(request, global_context, database_connection, redis_connection):
        
        email_verification_token = request.args.get('verification_token')

        print("email_verification_token", email_verification_token)

        if email_verification_token is None:
            return redirect('/auth/sign-in?broadcast=The verification token is invalid, please make sure the link is correct and try again'), 302
        
        token_data = database_connection['tokens'].find_one({'token_type': 'email_verification', 'token': email_verification_token})

        print("token_data", token_data)

        if token_data is None:
            return redirect('/auth/sign-in?broadcast=The verification token is invalid, please make sure the link is correct and try again'), 302
        
        user_data = database_connection['users'].find_one({'user_public_id': token_data['token_user_public_id']})

        if user_data is None:
            return redirect('/auth/sign-in?broadcast=The account associated with the verification token does not exist, please sign up'), 302
        
        if user_data['user_account_info']['user_account_verification_status'] == 'verified':
            return redirect('/auth/sign-in?broadcast=The account associated with the verification token is already verified, please sign in'), 302
        
        database_connection['users'].update_one({'user_public_id': user_data['user_public_id']}, {'$set': {'user_account_info.user_account_verification_status': 'verified'}})

        database_connection['tokens'].delete_one({'token_id': token_data['token']})

        global_context.session = generate_user_session(user_data, request, redis_connection, database_connection)

        return redirect('/?broadcast=The account has been verified successfully, welcome to ProjectRexa'), 302

def handle_resend_email_verification(request, global_context, database_connection):

    if verifiy_csrf_token(request, global_context) is False:
        return redirect('/auth/sign-in?broadcast=The CSRF token is invalid, please refresh the page and try again'), 302
    
    user_public_id = request.args.get('idenifier')
    
    if user_public_id is None:
        return redirect('/auth/sign-in?broadcast=The identifier is invalid, please go back and try again'), 302
    
    user_data = database_connection['users'].find_one({'user_public_id': user_public_id})

    if user_data is None:
        return redirect('/auth/sign-in?broadcast=The account associated with the identifier does not exist, please sign up'), 302
    
    if user_data['user_account_info']['user_account_verification_status'] == 'verified':
        return redirect('/auth/sign-in?broadcast=The account associated with the identifier is already verified, please sign in'), 302
    
    if user_data['user_account_info']['user_account_status'] == 'suspended':
        return redirect('/auth/sign-in?broadcast=The account associated with the identifier is suspended, please contact the support team'), 302
    
    if user_data['user_account_info']['user_account_status'] == 'deleted':
        return redirect('/auth/sign-in?broadcast=The account associated with the identifier is deleted, please contact the support team'), 302
    
    if database_connection['tokens'].find_one({'token_type': 'email_verification', 'token_user_public_id': user_data['user_public_id']}) is not None:
        if database_connection['tokens'].find_one({'token_type': 'email_verification', 'token_user_public_id': user_data['user_public_id']})['token_created_at'] > (datetime.datetime.now() - datetime.timedelta(hours=6)):
            return redirect('/auth/sign-in?broadcast=The verification email has already been sent, please check your inbox'), 302
    
    email_verification_token = generate_token('email_verification', user_data['user_public_id'], database_connection)

    send_email_verification_email(user_data['user_email'], user_data['user_profile_info']['user_full_name'], email_verification_token)

    return redirect('/auth/sign-in?broadcast=The verification email has been resent, please check your inbox'), 302

def handle_send_password_reset(request, global_context, database_connection):
    
    if verifiy_csrf_token(request, global_context) is False:
        return redirect('/auth/sign-in?broadcast=The CSRF token is invalid, please refresh the page and try again'), 302
    
    user_public_id = request.args.get('idenifier')
    
    if user_public_id is None:
        return redirect('/auth/sign-in?broadcast=The identifier is invalid, please go back and try again'), 302
    
    user_data = database_connection['users'].find_one({'user_public_id': user_public_id})

    if user_data is None:
        return redirect('/auth/sign-in?broadcast=The account associated with the identifier does not exist, please sign up'), 302
    
    if user_data['user_account_info']['user_account_status'] == 'suspended':
        return redirect('/auth/sign-in?broadcast=The account associated with the identifier is suspended, please contact the support team'), 302
    
    if user_data['user_account_info']['user_account_status'] == 'deleted':
        return redirect('/auth/sign-in?broadcast=The account associated with the identifier is deleted, please contact the support team'), 302
    
    if user_data['user_account_info']['user_password_last_updated_at'] > (datetime.datetime.now() - datetime.timedelta(days=1)):
        return redirect('/auth/sign-in?broadcast=The password has been reseted recently, therefore you cannot reset the password at the moment'), 302
    
    if database_connection['tokens'].find_one({'token_type': 'password_reset', 'token_user_public_id': user_data['user_public_id']}) is not None:
        if database_connection['tokens'].find_one({'token_type': 'password_reset', 'token_user_public_id': user_data['user_public_id']})['token_created_at'] > (datetime.datetime.now() - datetime.timedelta(hours=6)):
            return redirect('/auth/sign-in?broadcast=The password reset email has already been sent, please check your inbox'), 302
    
    password_reset_token = generate_token('password_reset', user_data['user_public_id'], database_connection)

    send_password_reset_email(user_data['user_email'], user_data['user_profile_info']['user_full_name'], password_reset_token)
    
    return redirect('/auth/sign-in?broadcast=The password reset email has been sent, please check your inbox'), 302

def handle_reset_password(request, global_context, database_connection, redis_connection):
    
    try:
        request_data = request.get_json()
    except:
        request_data = None

    if request_data is None:
        return jsonify({'status': 'error', 'message': 'The request data is invalid'}), 400
    
    password_reset_token = request_data.get('passwordResetToken')
    new_password = request_data.get('newPassword').strip()

    if password_reset_token is None:
        return jsonify({'status': 'error', 'message': 'The password reset token is invalid, please make sure the link is correct and try again'}), 400
    
    token_data = database_connection['tokens'].find_one({'token_type': 'password_reset', 'token': password_reset_token})

    if token_data is None:
        return jsonify({'status': 'error', 'message': 'The password reset token is invalid, please make sure the link is correct and try again'}), 400
    
    user_data = database_connection['users'].find_one({'user_public_id': token_data['token_user_public_id']})

    if user_data is None:
        return jsonify({'status': 'error', 'message': 'The account associated with the password reset token does not exist, please sign up'}), 400
    
    if user_data['user_account_info']['user_account_status'] == 'suspended':
        return jsonify({'status': 'error', 'message': 'The account associated with the password reset token is suspended, please contact the support team'}), 400
    
    if user_data['user_account_info']['user_account_status'] == 'deleted':
        return jsonify({'status': 'error', 'message': 'The account associated with the password reset token is deleted, please contact the support team'}), 400
    
    if user_data['user_account_info']['user_password_last_updated_at'] > (datetime.datetime.now() - datetime.timedelta(days=1)):
        return jsonify({'status': 'error', 'message': 'The password has been reseted recently, therefore you cannot reset the password at the moment'}), 400
    
    database_connection['users'].update_one({'user_public_id': user_data['user_public_id']}, {'$set': {'user_hashed_password': generate_hashed_password(new_password), 'user_account_info.user_password_last_updated_at': datetime.datetime.now()}})

    database_connection['tokens'].delete_one({'token': password_reset_token})

    redis_connection.delete(global_context.session['session_id'])

    global_context.session = generate_user_session(user_data, request, redis_connection, database_connection)

    return jsonify({'status': 'success', 'message': 'The password has been reseted successfully'}), 200