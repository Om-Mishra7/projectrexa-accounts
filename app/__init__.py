from config import CONFIG
import pickle
import datetime
import requests 
import mysql.connector
import redis
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response, g, abort, send_from_directory, send_file, Response


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
    if g.user.session.get("isLoggedIn"):
        return f"Hello, you are logged in using {g.user.session.get('loginMethod')}, session created at {str(g.user.session.get('sessionCreatedAt'))} and your oauth data is  {str(g.user.session.get('userData'))})"
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

@app.route("/oauth-initiater/reddit")
def oauth_initiater_reddit():
    if request.args.get("next") is not None:
        g.user.set("next", request.args.get("next"))
    
    if g.user.session.get("isLoggedIn"):
        return redirect(url_for("index"))
    
    oauth_state = secrets.token_urlsafe(32)
    g.user.set("oauthState", oauth_state, expire=300)
    
    return redirect(f"https://www.reddit.com/api/v1/authorize?client_id={CONFIG.REDDIT_CLIENT_ID}&response_type=code&state={oauth_state}&redirect_uri={CONFIG.REDDIT_REDIRECT_URI}&duration=permanent&scope=identity"), 302

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
            
    g.user.set("userData", github_user)
    g.user.set("isLoggedIn", True)
    g.user.set("loginMethod", "GITHUB")
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
        
    g.user.set("userData", google_user)
    g.user.set("isLoggedIn", True)
    g.user.set("loginMethod", "GOOGLE")
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
    
    print(discord_user)
    
    if discord_user.status_code != 200:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400
    
    discord_user = discord_user.json()
    
    g.user.set("userData", discord_user)
    g.user.set("isLoggedIn", True)
    g.user.set("loginMethod", "DISCORD")
    return redirect(url_for("index"))

@app.route("/oauth-callback/reddit")
def oauth_callback_reddit():
    if request.args.get("state") != g.user.session.get("oauthState"):
        return {"status": "error", "message": "Invalid OAuth State"}, 400
    
    # Delete oauthState from session
    g.user.session.pop("oauthState")
    
    if request.args.get("code") is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400
    
    oauth_code = request.args.get("code")
    
    reddit_token = requests.post('https://www.reddit.com/api/v1/access_token', data={'grant_type': 'authorization_code', 'code': oauth_code, 'redirect_uri': CONFIG.REDDIT_REDIRECT_URI}, auth=(CONFIG.REDDIT_CLIENT_ID, CONFIG.REDDIT_CLIENT_SECRET), timeout=3).json()
    
    print(reddit_token)
        
    if reddit_token is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400
    
    reddit_user = requests.get("https://oauth.reddit.com/api/v1/me", headers={"Authorization": f"Bearer {reddit_token}", "User-Agent": "ProjectRexa"}, timeout=3)
    
    print(reddit_user)
    
    if reddit_user.status_code != 200:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400
    
    reddit_user = reddit_user.json()
    
    g.user.set("userData", reddit_user)
    g.user.set("isLoggedIn", True)
    g.user.set("loginMethod", "REDDIT")
    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(debug=CONFIG.DEBUG,)