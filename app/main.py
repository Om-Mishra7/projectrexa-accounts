import pickle
import datetime
import random
import string
import requests 
import mysql.connector
import redis
import secrets
import re
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response, g, abort, send_from_directory, send_file, Response



load_dotenv()

class CONFIG:
    
    if os.getenv("SERVER_ENVIRONMENT") == "DEVELOPMENT":
        SERVER_ENVIRONMENT = "DEVELOPMENT"
        DEBUG = True
        TESTING = True
        GITHUB_REDIRECT_URI = "http://127.0.0.1:5000" + os.getenv("GITHUB_REDIRECT_URI")
        GOOGLE_REDIRECT_URI = "http://127.0.0.1:5000" + os.getenv("GOOGLE_REDIRECT_URI")
        DISCORD_REDIRECT_URI = "http://127.0.0.1:5000" + os.getenv("DISCORD_REDIRECT_URI")
        
        
        
    else:
        SERVER_ENVIRONMENT = "PRODUCTION"
        DEBUG = False
        TESTING = False
        GITHUB_REDIRECT_URI = "https://accounts.projectrexa.dedyn.io" + os.getenv("GITHUB_REDIRECT_URI")
        GOOGLE_REDIRECT_URI = "https://accounts.projectrexa.dedyn.io" + os.getenv("GOOGLE_REDIRECT_URI")
        DISCORD_REDIRECT_URI = "https://accounts.projectrexa.dedyn.io" + os.getenv("DISCORD_REDIRECT_URI")
        
    APPLICATION_SECRET_KEY = os.getenv("APPLICATION_SECRET_KEY")
    
    ATHER_API_KEY = os.getenv("ATHER_API_KEY")
    
    PLANETSCALE_DATABASE = os.getenv("PLANETSCALE_DATABASE")
    PLANETSCALE_DATABASE_HOST = os.getenv("PLANETSCALE_DATABASE_HOST")
    PLANETSCALE_DATABASE_USERNAME = os.getenv("PLANETSCALE_DATABASE_USERNAME")
    PLANETSCALE_DATABASE_PASSWORD = os.getenv("PLANETSCALE_DATABASE_PASSWORD")
    
    REDIS_DATABASE_URL = os.getenv("REDIS_DATABASE_URL")
    
    RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
    RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
    
    AUTHENTICATION_METHODS = ["EMAIL", "GITHUB", "GOOGLE", "DISCORD"]
    
    GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
    
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    
    DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
    DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
    
    TWITTER_CLIENT_ID = os.getenv("TWITTER_CLIENT_ID")
    TWITTER_CLIENT_SECRET = os.getenv("TWITTER_CLIENT_SECRET")


    
    

    
    
        


# User Class

class User:
    def __init__(self, session_id, session_binary):
        self.session_id = session_id
        self.session = pickle.loads(session_binary)
        
    def set(self, session_item_key, session_item_value, expire=None):
        self.session[session_item_key] = session_item_value
        if expire is not None:
            REDIS_DATABSE_CONNECTION.expire(self.session_id, expire)
        REDIS_DATABSE_CONNECTION.set(self.session_id, pickle.dumps(self.session))
        
    def clear_session(self):
        REDIS_DATABSE_CONNECTION.delete(self.session_id)
        self.session = {}
        self.session_id = None
        


# Helper Functions

def is_valid_session(session_id):
    if session_id is not None and len(session_id) == 43 and REDIS_DATABSE_CONNECTION.get(session_id) is not None:
        return True
    return False

def generate_session_id(session_ip_address=None):
    while True:
        session_id = secrets.token_urlsafe(32)
        if session_id not in REDIS_DATABSE_CONNECTION.keys():
            REDIS_DATABSE_CONNECTION.set(session_id, pickle.dumps({"sessionCreatedAt": datetime.datetime.now().timestamp(), "isLoggedIn": False, "createdIPAddress": session_ip_address}))
            return session_id

def sanitize_username(name):
    sanitized_name = re.sub(r'[^a-zA-Z0-9]', '', name)
    return sanitized_name.lower().replace(" ", "-")

def generate_username(name):
    username = name.lower().replace(" ", "-")
    while True:
        SQL_DATABASE_CURSOR.execute("SELECT * FROM Users WHERE Username = %s", (username,))
        if SQL_DATABASE_CURSOR.with_rows:
            # Fetch the result to avoid "Unread result found" error
            SQL_DATABASE_CURSOR.fetchall()

        if SQL_DATABASE_CURSOR.rowcount == 0:
            return username
        username = username + "-" + "".join(random.choices(string.ascii_lowercase, k=4))
        
def get_country_from_ip(ip_address):
    try:
        request = requests.get(f"https://ipapi.co/{ip_address}/country_name/", timeout=3).text
        if request.status_code == 200:
            return request.text.lower()
        return "Undefined"
    except:
        return "Undefined"
 
def generate_profile_id():
    while True:
        # ProfileID is a 8 digit number without 0 as the first digit
        profile_id = random.choice(string.digits[1:]) + ''.join(random.choices(string.digits, k=7))
        
        SQL_DATABASE_CURSOR.execute("SELECT * FROM Users WHERE ProfileID = %s", (profile_id,))
        if SQL_DATABASE_CURSOR.with_rows:
            # Fetch the result to avoid "Unread result found" error
            SQL_DATABASE_CURSOR.fetchall()

        if SQL_DATABASE_CURSOR.rowcount == 0:
            return profile_id       

def login_user(user_data):
    g.user.set("loggedIn", True)
    g.user.set("userID", user_data[0])
    g.user.set("userName", user_data[1])
    g.user.set("userFirstName", user_data[2])
    g.user.set("userLastName", user_data[3])
    g.user.set("userEmail", user_data[4])
    g.user.set("accountRole", user_data[9])
    g.user.set("profileImageURL", user_data[13])
    g.user.set("profileID", user_data[16])
    
    if user_data[14] == "EMAIL":
        g.user.set("emailVerified", user_data[15])
        g.user.set("signupMethod", user_data[14])
    else:
        g.user.set("emailVerified", True)
        g.user.set("signupMethod", user_data[14])
    
    SQL_DATABASE_CURSOR.execute("UPDATE Users SET LastLoginDate = %s WHERE Email = %s", (datetime.datetime.now(), user_data[4]))
    SQL_DATABASE_CONNECTION.commit()        
        
# SQL Database Connection

SQL_DATABASE_CONNECTION = mysql.connector.connect(
    host=CONFIG.PLANETSCALE_DATABASE_HOST,
    user=CONFIG.PLANETSCALE_DATABASE_USERNAME,
    password=CONFIG.PLANETSCALE_DATABASE_PASSWORD,
    database=CONFIG.PLANETSCALE_DATABASE,
    autocommit=True
)

SQL_DATABASE_CURSOR = SQL_DATABASE_CONNECTION.cursor()


# Redis Database Connection

REDIS_DATABSE_CONNECTION = redis.from_url(CONFIG.REDIS_DATABASE_URL)


# Flask Application

app = Flask(__name__)

app.config["SECRET_KEY"] = CONFIG.APPLICATION_SECRET_KEY

# App Context Processors

@app.context_processor
def inject_session():
    return dict(session=g.user.session)

# Decorators

@app.before_request
def check_session():
    session_id = request.cookies.get("projectrexa-session")
    
    
    if is_valid_session(session_id):
        g.user = User(session_id, REDIS_DATABSE_CONNECTION.get(session_id))
    else:
        session_id = generate_session_id(request.remote_addr)
        g.user = User(session_id, REDIS_DATABSE_CONNECTION.get(session_id))

            

@app.after_request
def set_session_cookie(response):
    if g.user.session_id:
        response.set_cookie("projectrexa-session", g.user.session_id, httponly=True, samesite="Lax", secure=True)
    return response

        
@app.route("/")
@app.route("/home")
def index():
    if g.user.session.get("loggedIn"):
        return f"Hello, {g.user.session.get('userName')}, session created at {g.user.session.get('sessionCreatedAt')} and your profile ID is {g.user.session.get('profileID')} and your profile image URL is {g.user.session.get('profileImageURL')}"
    return f"Hello, you are not logged in, session created at " + str(g.user.session.get("sessionCreatedAt"))


@app.route("/sign-in")
def sign_in():
    if request.args.get("next") is not None:
        g.user.set("next", request.args.get("next"))
    
    if request.args.get("method") is not None:
        if request.args.get("method").upper() in CONFIG.AUTHENTICATION_METHODS:
            if request.args.get("method").upper() == "EMAIL":
                return render_template("sign_in.html", methods= ["EMAIL"])
            else:
                return redirect(url_for(f"oauth_initiater_{request.args.get('method').lower()}")), 302

    return render_template("sign_in.html", methods= CONFIG.AUTHENTICATION_METHODS)

@app.route("/sign-out")
def sign_out():
    g.user.clear_session()
    return redirect(url_for("sign_in")) 


# OAuth Initiaters

@app.route("/oauth-initiater/github")
def oauth_initiater_github():
    if request.args.get("next") is not None:
        g.user.set("next", request.args.get("next"))
    
    if g.user.session.get("isLoggedIn"):
        return redirect(url_for("index"))
    
    oauth_state = secrets.token_urlsafe(32)
    g.user.set("oauthState", oauth_state, expire=300)
    
        
    return redirect(f"https://github.com/login/oauth/authorize?client_id={CONFIG.GITHUB_CLIENT_ID}&redirect_uri={CONFIG.GITHUB_REDIRECT_URI}&state={oauth_state}&scope=user:email&allow_signup=true"), 302
                    
@app.route("/oauth-initiater/google")
def oauth_initiater_google():
    if request.args.get("next") is not None:
        g.user.set("next", request.args.get("next"))
    
    if g.user.session.get("isLoggedIn"):
        return redirect(url_for("index"))
    
    oauth_state = secrets.token_urlsafe(32)
    g.user.set("oauthState", oauth_state, expire=300)
        
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?client_id={CONFIG.GOOGLE_CLIENT_ID}&redirect_uri={CONFIG.GOOGLE_REDIRECT_URI}&response_type=code&scope=openid%20email%20profile&state={oauth_state}"), 302

@app.route("/oauth-initiater/discord")
def oauth_initiater_discord():
    if request.args.get("next") is not None:
        g.user.set("next", request.args.get("next"))
    
    if g.user.session.get("isLoggedIn"):
        return redirect(url_for("index"))
    
    oauth_state = secrets.token_urlsafe(32)
    g.user.set("oauthState", oauth_state, expire=300)
    
    return redirect(f"https://discord.com/api/oauth2/authorize?client_id={CONFIG.DISCORD_CLIENT_ID}&redirect_uri={CONFIG.DISCORD_REDIRECT_URI}&response_type=code&scope=identify%20email&state={oauth_state}"), 302


# OAuth Callbacks

@app.route("/oauth-callback/github")
def oauth_callback_github():
    if request.args.get("state") != g.user.session.get("oauthState"):
        return {"status": "error", "message": "Invalid OAuth State"}, 400
    
    # Delete oauthState from session
    g.user.session.pop("oauthState")
    
    if request.args.get("code") is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400
    
    oauth_code = request.args.get("code")
    
    github_token = requests.post(f'https://github.com/login/oauth/access_token?client_id={CONFIG.GITHUB_CLIENT_ID}&client_secret={CONFIG.GITHUB_CLIENT_SECRET}&code={oauth_code}', headers={'Accept': 'application/json'}, timeout=3).json().get("access_token")
    
    if github_token is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400
    
    github_user = requests.get("https://api.github.com/user", headers={"Authorization": f"token {github_token}"}, timeout=3).json()
    
    
    if github_user.get("email") is None:
        github_user_emails = requests.get("https://api.github.com/user/emails", headers={"Authorization": f"token {github_token}"}, timeout=3).json()
        
        for email in github_user_emails:
            if email.get("primary"):
                github_user["email"] = email.get("email")
                break
            
    SQL_DATABASE_CURSOR.execute("SELECT * FROM Users WHERE email = %s", (github_user.get("email"),))
    
    user_data = SQL_DATABASE_CURSOR.fetchone()
        
    if user_data is None:
        try:
            profileID = generate_profile_id()

            SQL_DATABASE_CURSOR.execute("INSERT INTO Users (Username, FirstName, LastName, Email, RegistrationCountry, AccountRole, ProfileImageURL, SignupMethod, EmailVerified, ProfileID) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                                    (generate_username(github_user.get("name")), 
                                     github_user.get("name").split(" ")[0].title(), 
                                     github_user.get("name").split(" ")[1].title() if len(github_user.get("name").split(" ")) > 1 else "", 
                                     github_user.get("email").lower(), 
                                     get_country_from_ip(g.user.session.get("createdIPAddress")), 
                                     "USER", 
                                     f"https://cdn.projectrexa.dedyn.io/projectrexa/user-content/avatars/{profileID}.png",
                                     "GITHUB", 
                                     True, 
                                     profileID
                                    ))
            
            SQL_DATABASE_CONNECTION.commit()
            
        except Exception as error:
            SQL_DATABASE_CONNECTION.rollback()

        
        
        
    SQL_DATABASE_CURSOR.execute("SELECT * FROM Users WHERE email = %s", (github_user.get("email"),))
    user_data = SQL_DATABASE_CURSOR.fetchone()
    
    try:
        profile_picture_data = requests.get(github_user.get("avatar_url"), timeout=3).content
        requests.post("https://ather.api.projectrexa.dedyn.io/upload", files={'file': profile_picture_data}, data={
                                    'key': f'projectrexa/user-content/avatars/{user_data[16]}.png', 'content_type': 'image/png', 'public': 'true'}, headers={'X-Authorization': CONFIG.ATHER_API_KEY, 'cf-identity': 'RqauQSGYqhW0j8x6Q9G7v'}, timeout=5).text
    except:
        pass
    
    login_user(user_data)
    
    
    return redirect(url_for("index"))
    
    
    
                                                             

@app.route("/oauth-callback/google")
def oauth_callback_google():
    if request.args.get("state") != g.user.session.get("oauthState"):
        return {"status": "error", "message": "Invalid OAuth State"}, 400
    
    # Delete oauthState from session
    g.user.session.pop("oauthState")
    
    if request.args.get("code") is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400
    
    oauth_code = request.args.get("code")
    
    google_token = requests.post(f'https://oauth2.googleapis.com/token?client_id={CONFIG.GOOGLE_CLIENT_ID}&client_secret={CONFIG.GOOGLE_CLIENT_SECRET}&code={oauth_code}&grant_type=authorization_code&redirect_uri={CONFIG.GOOGLE_REDIRECT_URI}', headers={'Accept': 'application/json'}, timeout=3).json().get("access_token")
    
    if google_token is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400
    
    google_user = requests.get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=" + google_token, timeout=3).json()
        
    SQL_DATABASE_CURSOR.execute("SELECT * FROM Users WHERE email = %s", (google_user.get("email"),))

    user_data = SQL_DATABASE_CURSOR.fetchone()

    if user_data is None:
        try:
            profileID = generate_profile_id()

            SQL_DATABASE_CURSOR.execute("INSERT INTO Users (Username, FirstName, LastName, Email, RegistrationCountry, AccountRole, ProfileImageURL, SignupMethod, EmailVerified, ProfileID) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                                    (generate_username(google_user.get("name")), 
                                     google_user.get("given_name"), 
                                     google_user.get("family_name"), 
                                     google_user.get("email").lower(), 
                                     get_country_from_ip(g.user.session.get("createdIPAddress")), 
                                     "USER", 
                                     f"https://cdn.projectrexa.dedyn.io/projectrexa/user-content/avatars/{profileID}.png",
                                     "GOOGLE", 
                                     True, 
                                     profileID
                                    ))
            
            SQL_DATABASE_CONNECTION.commit()
            
        except Exception as error:
            SQL_DATABASE_CONNECTION.rollback()

    
    SQL_DATABASE_CURSOR.execute("SELECT * FROM Users WHERE email = %s", (google_user.get("email"),))
    user_data = SQL_DATABASE_CURSOR.fetchone()


    try:
        profile_picture_data = requests.get(google_user.get("picture"), timeout=3).content
        requests.post("https://ather.api.projectrexa.dedyn.io/upload", files={'file': profile_picture_data}, data={
                                    'key': f'projectrexa/user-content/avatars/{user_data[16]}.png', 'content_type': 'image/png', 'public': 'true'}, headers={'X-Authorization': CONFIG.ATHER_API_KEY, 'cf-identity': 'RqauQSGYqhW0j8x6Q9G7v'}, timeout=5)
    except:
        pass

    login_user(user_data)

    return redirect(url_for("index"))

@app.route("/oauth-callback/discord")
def oauth_callback_discord():
    if request.args.get("state") != g.user.session.get("oauthState"):
        return {"status": "error", "message": "Invalid OAuth State"}, 400
    
    # Delete oauthState from session
    g.user.session.pop("oauthState")
    
    if request.args.get("code") is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400
    
    oauth_code = request.args.get("code")
    
    discord_token = requests.post('https://discord.com/api/oauth2/token', data={'client_id': CONFIG.DISCORD_CLIENT_ID, 'client_secret': CONFIG.DISCORD_CLIENT_SECRET, 'grant_type': 'authorization_code', 'code': oauth_code, 'redirect_uri': CONFIG.DISCORD_REDIRECT_URI, 'scope': 'identify email'}, headers={'Content-Type': 'application/x-www-form-urlencoded'}, timeout=3).json().get("access_token")
        
    if discord_token is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400
    
    discord_user = requests.get("https://discord.com/api/users/@me", headers={"Authorization": f"Bearer {discord_token}"}, timeout=3)
        
    if discord_user.status_code != 200:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400
    
    discord_user = discord_user.json()
    
    SQL_DATABASE_CURSOR.execute("SELECT * FROM Users WHERE email = %s", (discord_user.get("email"),))

    user_data = SQL_DATABASE_CURSOR.fetchone()

    if user_data is None:
        try:
            profileID = generate_profile_id()

            SQL_DATABASE_CURSOR.execute("INSERT INTO Users (Username, FirstName, LastName, Email, RegistrationCountry, AccountRole, ProfileImageURL, SignupMethod, EmailVerified, ProfileID) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                                    (generate_username(discord_user.get("username")), 
                                     discord_user.get("username"), 
                                     "", 
                                     discord_user.get("email").lower(), 
                                     get_country_from_ip(g.user.session.get("createdIPAddress")), 
                                     "USER", 
                                     f"https://cdn.projectrexa.dedyn.io/projectrexa/user-content/avatars/{profileID}.png",
                                     "DISCORD", 
                                     True, 
                                     profileID
                                    ))
            
            SQL_DATABASE_CONNECTION.commit()
            
        except Exception as error:
            SQL_DATABASE_CONNECTION.rollback()

    SQL_DATABASE_CURSOR.execute("SELECT * FROM Users WHERE email = %s", (discord_user.get("email"),))

    user_data = SQL_DATABASE_CURSOR.fetchone()

    try:
        profile_picture_data = requests.get(f"https://cdn.discordapp.com/avatars/{discord_user.get('id')}/{discord_user.get('avatar')}.png", timeout=3).content
        requests.post("https://ather.api.projectrexa.dedyn.io/upload", files={'file': profile_picture_data}, data={
                                    'key': f'projectrexa/user-content/avatars/{user_data[16]}.png', 'content_type': 'image/png', 'public': 'true'}, headers={'X-Authorization': CONFIG.ATHER_API_KEY, 'cf-identity': 'RqauQSGYqhW0j8x6Q9G7v'}, timeout=5)
    except:
        pass

    login_user(user_data)

    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(debug=CONFIG.DEBUG,)