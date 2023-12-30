import pickle
import datetime
import bcrypt
import random
import string
import requests
import mysql.connector
import redis
import secrets
import re
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, g, jsonify
import uuid
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException


load_dotenv()


class CONFIG:
    if os.getenv("SERVER_ENVIRONMENT") == "DEVELOPMENT":
        SERVER_ENVIRONMENT = "DEVELOPMENT"
        DEBUG = True
        TESTING = True
        GITHUB_REDIRECT_URI = "http://127.0.0.1:5000" + os.getenv("GITHUB_REDIRECT_URI")
        GOOGLE_REDIRECT_URI = "http://127.0.0.1:5000" + os.getenv("GOOGLE_REDIRECT_URI")
        DISCORD_REDIRECT_URI = "http://127.0.0.1:5000" + os.getenv(
            "DISCORD_REDIRECT_URI"
        )

    else:
        SERVER_ENVIRONMENT = "PRODUCTION"
        DEBUG = False
        TESTING = False
        GITHUB_REDIRECT_URI = "https://accounts.projectrexa.dedyn.io" + os.getenv(
            "GITHUB_REDIRECT_URI"
        )
        GOOGLE_REDIRECT_URI = "https://accounts.projectrexa.dedyn.io" + os.getenv(
            "GOOGLE_REDIRECT_URI"
        )
        DISCORD_REDIRECT_URI = "https://accounts.projectrexa.dedyn.io" + os.getenv(
            "DISCORD_REDIRECT_URI"
        )

    APPLICATION_SECRET_KEY = os.getenv("APPLICATION_SECRET_KEY")

    SENDINBLUE_API_KEY = os.getenv("SENDINBLUE_API_KEY")

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
    if (
        session_id is not None
        and len(session_id) == 43
        and REDIS_DATABSE_CONNECTION.get(session_id) is not None
    ):
        return True
    return False


def generate_session_id(session_ip_address=None):
    while True:
        session_id = secrets.token_urlsafe(32)
        if session_id not in REDIS_DATABSE_CONNECTION.keys():
            REDIS_DATABSE_CONNECTION.set(
                session_id,
                pickle.dumps(
                    {
                        "sessionCreatedAt": datetime.datetime.now().timestamp(),
                        "loggedIn": False,
                        "createdIPAddress": session_ip_address,
                    }
                ),
            )
            return session_id


def sanitize_username(name):
    sanitized_name = re.sub(r"[^a-zA-Z0-9]", "", name)
    return sanitized_name.lower().replace(" ", "-")


def sanitize_useremail(email):
    sanitized_email = re.sub(r"[^a-zA-Z0-9@._-]", "", email)
    return sanitized_email.lower()


def generate_username(name):
    username = name.lower().replace(" ", "-")
    while True:
        SQL_DATABASE_CURSOR.execute(
            "SELECT * FROM Users WHERE Username = %s", (username,)
        )
        if SQL_DATABASE_CURSOR.with_rows:
            # Fetch the result to avoid "Unread result found" error
            SQL_DATABASE_CURSOR.fetchall()

        if SQL_DATABASE_CURSOR.rowcount == 0:
            return username
        username = username + "-" + "".join(random.choices(string.ascii_lowercase, k=4))


def get_country_from_ip(ip_address):
    try:
        request = requests.get(
            f"http://ip-api.com/json/{ip_address}?fields=status,countryCode", timeout=3
        )
        if request.status_code == 200:
            if request.json().get("status") == "success":
                return request.json().get("countryCode")
        return "Undefined"
    except:
        return "Undefined"


def generate_profile_id():
    while True:
        # ProfileID is a 8 digit number without 0 as the first digit
        profile_id = random.choice(string.digits[1:]) + "".join(
            random.choices(string.digits, k=7)
        )

        SQL_DATABASE_CURSOR.execute(
            "SELECT * FROM Users WHERE ProfileID = %s", (profile_id,)
        )
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

    SQL_DATABASE_CURSOR.execute(
        "UPDATE Users SET LastLoginDate = %s WHERE Email = %s",
        (datetime.datetime.now(), user_data[4]),
    )
    SQL_DATABASE_CONNECTION.commit()


def verify_recaptcha(response):
    if response is None:
        return False

    try:
        request = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": CONFIG.RECAPTCHA_SECRET_KEY, "response": response},
            timeout=3,
        )
        if request.status_code == 200:
            if request.json().get("success"):
                return True
        return False
    except:
        return False


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def verify_hashed_password(password, hashed_password):
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))


def send_email(recipient_email_address, recipient_name, template_name, token=None):
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key["api-key"] = CONFIG.SENDINBLUE_API_KEY

    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration)
    )

    if template_name == "user-registration":
        subject = f"Welcome to ProjectRexa!"
        sender = {
            "name": "ProjectRexa Account Notifications",
            "email": "noreply@projectrexa.dedyn.io",
        }
        to = [{"email": recipient_email_address, "name": recipient_name}]
        reply_to = {
            "email": "account@projectrexa.dedyn.io",
            "name": "ProjectRexa Account Support",
        }

        token_url = (
            f"https://accounts.projectrexa.dedyn.io/api/v1/verify-email?token={token}"
        )
        html = render_template(
            "email/user-registration.html",
            token_url=token_url,
            user_name=recipient_name,
        )

    elif template_name == "user-password-reset":
        subject = f"Reset your password | ProjectRexa"
        sender = {
            "name": "ProjectRexa Account Notifications",
            "email": "noreply@projectrexa.dedyn.io",
        }
        to = [{"email": recipient_email_address, "name": recipient_name}]
        reply_to = {
            "email": "account@projectrexa.dedyn.io",
            "name": "ProjectRexa Account Support",
        }

        token_url = (
            f"https://accounts.projectrexa.dedyn.io/reset-password?token={token}"
        )

        html = render_template(
            "email/user-password-reset.html",
            token_url=token_url,
            user_name=recipient_name,
        )
    else:
        return False

    try:
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            to=to, html_content=html, reply_to=reply_to, sender=sender, subject=subject
        )
        api_instance.send_transac_email(send_smtp_email)
        return True

    except ApiException as e:
        print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)
        return False


# SQL Database Connection

SQL_DATABASE_CONNECTION = mysql.connector.connect(
    host=CONFIG.PLANETSCALE_DATABASE_HOST,
    user=CONFIG.PLANETSCALE_DATABASE_USERNAME,
    password=CONFIG.PLANETSCALE_DATABASE_PASSWORD,
    database=CONFIG.PLANETSCALE_DATABASE,
    autocommit=True,
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
    response.headers["Access-Control-Allow-Origin"] = "https://*.projectrexa.dedyn.io"
    response.headers["Access-Control-Allow-Methods"] = "POST"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    if g.user.session_id:
        response.set_cookie(
            "projectrexa-session",
            g.user.session_id,
            httponly=True,
            samesite="None",
            secure=True,
        )
    return response


@app.route("/", methods=["GET", "POST"])
def index():
    if g.user.session.get("loggedIn"):
        return (
            jsonify(
                {
                    "status": "success",
                    "message": "You are logged in to your ProjectRexa Account",
                    "requestID": uuid.uuid4().hex,
                }
            ),
            200,
        )
    return (
        jsonify(
            {
                "status": "error",
                "message": "You are not logged in to your ProjectRexa Account",
                "requestID": uuid.uuid4().hex,
            }
        ),
        401,
    )


@app.route("/sign-in")
def sign_in():
    if g.user.session.get("loggedIn"):
        return redirect(url_for("index"))

    if request.args.get("next") is not None:
        g.user.set("next", request.args.get("next"))

    if request.args.get("method") is not None:
        if request.args.get("method").upper() in CONFIG.AUTHENTICATION_METHODS:
            if request.args.get("method").upper() == "EMAIL":
                return render_template("sign_in.html", methods=["EMAIL"])
            else:
                return (
                    redirect(
                        url_for(f"oauth_initiater_{request.args.get('method').lower()}")
                    ),
                    302,
                )

    return render_template("sign_in.html", methods=CONFIG.AUTHENTICATION_METHODS)


@app.route("/sign-up")
def sign_up():
    if request.args.get("next") is not None:
        g.user.set("next", request.args.get("next"))

    if g.user.session.get("loggedIn"):
        return redirect(url_for("index"))

    return render_template("sign_up.html", methods=CONFIG.AUTHENTICATION_METHODS)


@app.route("/sign-out")
def sign_out():
    g.user.clear_session()
    return redirect(url_for("sign_in"))


@app.route("/reset-password")
def reset_password():
    if request.args.get("next") is not None:
        g.user.set("next", request.args.get("next"))

    if g.user.session.get("loggedIn"):
        return redirect(url_for("index"))

    if request.args.get("token") is None:
        return redirect(
            url_for(
                "sign_in",
                alert="The password reset link was invalid please make sure you copied the link correctly",
                alertType="info",
            )
        )

    return render_template("reset_password.html")


@app.route("/favicon.ico")
def favicon():
    return redirect("https://cdn.projectrexa.dedyn.io/favicon.ico", 302)


# OAuth Initiaters


@app.route("/oauth-initiater/github")
def oauth_initiater_github():
    if request.args.get("next") is not None:
        g.user.set("next", request.args.get("next"))

    if g.user.session.get("loggedIn"):
        return redirect(url_for("index"))

    oauth_state = secrets.token_urlsafe(32)
    g.user.set("oauthState", oauth_state, expire=300)

    return (
        redirect(
            f"https://github.com/login/oauth/authorize?client_id={CONFIG.GITHUB_CLIENT_ID}&redirect_uri={CONFIG.GITHUB_REDIRECT_URI}&state={oauth_state}&scope=user:email&allow_signup=true"
        ),
        302,
    )


@app.route("/oauth-initiater/google")
def oauth_initiater_google():
    if request.args.get("next") is not None:
        g.user.set("next", request.args.get("next"))

    if g.user.session.get("loggedIn"):
        return redirect(url_for("index"))

    oauth_state = secrets.token_urlsafe(32)
    g.user.set("oauthState", oauth_state, expire=300)

    return (
        redirect(
            f"https://accounts.google.com/o/oauth2/v2/auth?client_id={CONFIG.GOOGLE_CLIENT_ID}&redirect_uri={CONFIG.GOOGLE_REDIRECT_URI}&response_type=code&scope=openid%20email%20profile&state={oauth_state}"
        ),
        302,
    )


@app.route("/oauth-initiater/discord")
def oauth_initiater_discord():
    if request.args.get("next") is not None:
        g.user.set("next", request.args.get("next"))

    if g.user.session.get("loggedIn"):
        return redirect(url_for("index"))

    oauth_state = secrets.token_urlsafe(32)
    g.user.set("oauthState", oauth_state, expire=300)

    return (
        redirect(
            f"https://discord.com/api/oauth2/authorize?client_id={CONFIG.DISCORD_CLIENT_ID}&redirect_uri={CONFIG.DISCORD_REDIRECT_URI}&response_type=code&scope=identify%20email&state={oauth_state}"
        ),
        302,
    )


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

    github_token = (
        requests.post(
            f"https://github.com/login/oauth/access_token?client_id={CONFIG.GITHUB_CLIENT_ID}&client_secret={CONFIG.GITHUB_CLIENT_SECRET}&code={oauth_code}",
            headers={"Accept": "application/json"},
            timeout=3,
        )
        .json()
        .get("access_token")
    )

    if github_token is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400

    github_user = requests.get(
        "https://api.github.com/user",
        headers={"Authorization": f"token {github_token}"},
        timeout=3,
    ).json()

    if github_user.get("email") is None:
        github_user_emails = requests.get(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"token {github_token}"},
            timeout=3,
        ).json()

        for email in github_user_emails:
            if email.get("primary"):
                github_user["email"] = email.get("email")
                break

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Users WHERE email = %s", (github_user.get("email"),)
    )

    user_data = SQL_DATABASE_CURSOR.fetchone()

    if user_data is not None:
        if user_data[14] != "GITHUB":
            return redirect(
                url_for(
                    "sign_in",
                    alert="This email address is associated with a different sign in method",
                    alertType="danger",
                )
            )

    if user_data is None:
        try:
            profileID = generate_profile_id()

            SQL_DATABASE_CURSOR.execute(
                "INSERT INTO Users (Username, FirstName, LastName, Email, RegistrationCountry, AccountRole, ProfileImageURL, SignupMethod, EmailVerified, ProfileID) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    generate_username(github_user.get("name")),
                    github_user.get("name").split(" ")[0].title(),
                    github_user.get("name").split(" ")[1].title()
                    if len(github_user.get("name").split(" ")) > 1
                    else "",
                    github_user.get("email").lower(),
                    get_country_from_ip(g.user.session.get("createdIPAddress")),
                    "USER",
                    f"https://cdn.projectrexa.dedyn.io/projectrexa/user-content/avatars/{profileID}.png",
                    "GITHUB",
                    True,
                    profileID,
                ),
            )

            SQL_DATABASE_CONNECTION.commit()

        except Exception as error:
            SQL_DATABASE_CONNECTION.rollback()

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Users WHERE email = %s", (github_user.get("email"),)
    )
    user_data = SQL_DATABASE_CURSOR.fetchone()

    try:
        profile_picture_data = requests.get(
            github_user.get("avatar_url"), timeout=3
        ).content
        requests.post(
            "https://ather.api.projectrexa.dedyn.io/upload",
            files={"file": profile_picture_data},
            data={
                "key": f"projectrexa/user-content/avatars/{user_data[16]}.png",
                "content_type": "image/png",
                "public": "true",
            },
            headers={
                "X-Authorization": CONFIG.ATHER_API_KEY,
                "cf-identity": "RqauQSGYqhW0j8x6Q9G7v",
            },
            timeout=5,
        ).text
    except:
        pass

    login_user(user_data)

    return (
        redirect(g.user.session.get("next"))
        if g.user.session.get("next")
        else redirect(url_for("index"))
    )


@app.route("/oauth-callback/google")
def oauth_callback_google():
    if request.args.get("state") != g.user.session.get("oauthState"):
        return {"status": "error", "message": "Invalid OAuth State"}, 400

    # Delete oauthState from session
    g.user.session.pop("oauthState")

    if request.args.get("code") is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400

    oauth_code = request.args.get("code")

    google_token = (
        requests.post(
            f"https://oauth2.googleapis.com/token?client_id={CONFIG.GOOGLE_CLIENT_ID}&client_secret={CONFIG.GOOGLE_CLIENT_SECRET}&code={oauth_code}&grant_type=authorization_code&redirect_uri={CONFIG.GOOGLE_REDIRECT_URI}",
            headers={"Accept": "application/json"},
            timeout=3,
        )
        .json()
        .get("access_token")
    )

    if google_token is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400

    google_user = requests.get(
        "https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token="
        + google_token,
        timeout=3,
    ).json()

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Users WHERE email = %s", (google_user.get("email"),)
    )

    user_data = SQL_DATABASE_CURSOR.fetchone()

    if user_data is not None:
        if user_data[14] != "GOOGLE":
            return redirect(
                url_for(
                    "sign_in",
                    alert="This email address is associated with a different sign in method",
                    alertType="danger",
                )
            )

    if user_data is None:
        try:
            profileID = generate_profile_id()

            SQL_DATABASE_CURSOR.execute(
                "INSERT INTO Users (Username, FirstName, LastName, Email, RegistrationCountry, AccountRole, ProfileImageURL, SignupMethod, EmailVerified, ProfileID) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    generate_username(google_user.get("name")),
                    google_user.get("given_name").title(),
                    google_user.get("family_name").title(),
                    google_user.get("email").lower(),
                    get_country_from_ip(g.user.session.get("createdIPAddress")),
                    "USER",
                    f"https://cdn.projectrexa.dedyn.io/projectrexa/user-content/avatars/{profileID}.png",
                    "GOOGLE",
                    True,
                    profileID,
                ),
            )

            SQL_DATABASE_CONNECTION.commit()

        except Exception as error:
            SQL_DATABASE_CONNECTION.rollback()

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Users WHERE email = %s", (google_user.get("email"),)
    )
    user_data = SQL_DATABASE_CURSOR.fetchone()

    try:
        profile_picture_data = requests.get(
            google_user.get("picture"), timeout=3
        ).content
        requests.post(
            "https://ather.api.projectrexa.dedyn.io/upload",
            files={"file": profile_picture_data},
            data={
                "key": f"projectrexa/user-content/avatars/{user_data[16]}.png",
                "content_type": "image/png",
                "public": "true",
            },
            headers={
                "X-Authorization": CONFIG.ATHER_API_KEY,
                "cf-identity": "RqauQSGYqhW0j8x6Q9G7v",
            },
            timeout=5,
        )
    except:
        pass

    login_user(user_data)

    return (
        redirect(g.user.session.get("next"))
        if g.user.session.get("next")
        else redirect(url_for("index"))
    )


@app.route("/oauth-callback/discord")
def oauth_callback_discord():
    if request.args.get("state") != g.user.session.get("oauthState"):
        return {"status": "error", "message": "Invalid OAuth State"}, 400

    # Delete oauthState from session
    g.user.session.pop("oauthState")

    if request.args.get("code") is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400

    oauth_code = request.args.get("code")

    discord_token = (
        requests.post(
            "https://discord.com/api/oauth2/token",
            data={
                "client_id": CONFIG.DISCORD_CLIENT_ID,
                "client_secret": CONFIG.DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": oauth_code,
                "redirect_uri": CONFIG.DISCORD_REDIRECT_URI,
                "scope": "identify email",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=3,
        )
        .json()
        .get("access_token")
    )

    if discord_token is None:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400

    discord_user = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {discord_token}"},
        timeout=3,
    )

    if discord_user.status_code != 200:
        return {"status": "error", "message": "Invalid OAuth Code"}, 400

    discord_user = discord_user.json()

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Users WHERE email = %s", (discord_user.get("email"),)
    )

    user_data = SQL_DATABASE_CURSOR.fetchone()

    if user_data is not None:
        if user_data[14] != "DISCORD":
            return redirect(
                url_for(
                    "sign_in",
                    alert="This email address is associated with a different sign in method",
                    alertType="danger",
                )
            )

    if user_data is None:
        try:
            profileID = generate_profile_id()

            SQL_DATABASE_CURSOR.execute(
                "INSERT INTO Users (Username, FirstName, LastName, Email, RegistrationCountry, AccountRole, ProfileImageURL, SignupMethod, EmailVerified, ProfileID) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    generate_username(discord_user.get("username")),
                    discord_user.get("username"),
                    "User",
                    discord_user.get("email").lower(),
                    get_country_from_ip(g.user.session.get("createdIPAddress")),
                    "USER",
                    f"https://cdn.projectrexa.dedyn.io/projectrexa/user-content/avatars/{profileID}.png",
                    "DISCORD",
                    True,
                    profileID,
                ),
            )

            SQL_DATABASE_CONNECTION.commit()

        except Exception as error:
            SQL_DATABASE_CONNECTION.rollback()

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Users WHERE email = %s", (discord_user.get("email"),)
    )

    user_data = SQL_DATABASE_CURSOR.fetchone()

    try:
        profile_picture_data = requests.get(
            f"https://cdn.discordapp.com/avatars/{discord_user.get('id')}/{discord_user.get('avatar')}.png",
            timeout=3,
        ).content
        requests.post(
            "https://ather.api.projectrexa.dedyn.io/upload",
            files={"file": profile_picture_data},
            data={
                "key": f"projectrexa/user-content/avatars/{user_data[16]}.png",
                "content_type": "image/png",
                "public": "true",
            },
            headers={
                "X-Authorization": CONFIG.ATHER_API_KEY,
                "cf-identity": "RqauQSGYqhW0j8x6Q9G7v",
            },
            timeout=5,
        )
    except:
        pass

    login_user(user_data)

    return (
        redirect(g.user.session.get("next"))
        if g.user.session.get("next")
        else redirect(url_for("index"))
    )


# API Endpoints


@app.route("/api/v1/sign-in", methods=["POST"])
def api_sign_in():
    if (
        request.json.get("email") is None
        or request.json.get("password") is None
        or request.json.get("reCaptchaResponse") is None
    ):
        return {
            "status": "error",
            "message": "The request is invalid or missing a required parameter",
        }, 400

    if not verify_recaptcha(request.json.get("reCaptchaResponse")):
        return {"status": "error", "message": "Invalid reCAPTCHA response"}, 400

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Users WHERE email = %s", (request.json.get("email").lower(),)
    )

    user_data = SQL_DATABASE_CURSOR.fetchone()

    if user_data is None:
        return {
            "status": "error",
            "message": "No account has been registered with this email address",
        }, 400

    if not user_data[15]:
        return {
            "status": "error",
            "message": "Email address is not yet verified, <a onclick='handleResendVerificationEmail()' href='#'>click here</a> to resend the verification email",
        }, 400

    if user_data[14] != "EMAIL":
        return {
            "status": "error",
            "message": "This email address is associated with a different sign in method",
        }, 400

    user_password = request.json.get("password")
    if not verify_hashed_password(user_password, user_data[5]):
        return {
            "status": "error",
            "message": "Incorrect password, <a onclick='handleResetPassword()' href='#'>click here</a> to reset your password",
        }, 400

    if user_data[10] != "Active":
        return {
            "status": "error",
            "message": f"Your account has been {user_data[10].lower()}, <a href='mailto:account@projectrexa.dedyn.io'>contact us</a> for more information",
        }, 400

    if not verify_hashed_password(request.json.get("password"), user_data[5]):
        return {
            "status": "error",
            "message": "Incorrect password, <a href='/forgot-password'>click here</a> to reset your password",
        }, 400

    login_user(user_data)

    return {
        "status": "success",
        "message": "Signed In Successfully",
        "redirect": g.user.session.get("next")
        if g.user.session.get("next")
        else url_for("index"),
    }, 200


@app.route("/api/v1/sign-up", methods=["POST"])
def api_sign_up():
    if (
        request.json.get("firstName") is None
        or request.json.get("lastName") is None
        or request.json.get("email") is None
        or request.json.get("password") is None
        or request.json.get("reCaptchaResponse") is None
    ):
        return {
            "status": "error",
            "message": "The request is invalid or missing a required parameter",
        }, 400

    request.json["firstName"] = request.json.get("firstName").strip()
    request.json["lastName"] = request.json.get("lastName").strip()
    request.json["email"] = sanitize_useremail(request.json.get("email").lower())

    if not re.match(r"[^@]+@[^@]+\.[^@]+", request.json.get("email")):
        return {
            "status": "error",
            "message": "The email address provided was invalid, check the email address and try again",
        }, 400

    if not verify_recaptcha(request.json.get("reCaptchaResponse")):
        return {"status": "error", "message": "Invalid reCAPTCHA response"}, 400

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Users WHERE email = %s", (request.json.get("email").lower(),)
    )

    user_data = SQL_DATABASE_CURSOR.fetchone()

    if user_data is not None:
        return {
            "status": "error",
            "message": "An account has already been registered with this email address",
        }, 400

    EMAIL_VERIFICATION_TOKEN = secrets.token_urlsafe(32)

    SQL_DATABASE_CURSOR.execute(
        "INSERT INTO Tokens (TokenValue, TokenIssuedTo, TokenAuthority, TokenUsed) VALUES (%s, %s, %s, %s)",
        (
            EMAIL_VERIFICATION_TOKEN,
            request.json.get("email").lower(),
            "EMAIL_VERIFICATION",
            False,
        ),
    )

    if not send_email(
        request.json.get("email").lower(),
        request.json.get("firstName").title()
        + " "
        + request.json.get("lastName").title(),
        "user-registration",
        EMAIL_VERIFICATION_TOKEN,
    ):
        return {
            "status": "error",
            "message": "Our internal services are facing some issues, please try again later",
        }, 500

    try:
        profileID = generate_profile_id()

        SQL_DATABASE_CURSOR.execute(
            "INSERT INTO Users (Username, FirstName, LastName, Email, PasswordHash, RegistrationCountry, AccountRole, ProfileImageURL, SignupMethod, EmailVerified, ProfileID) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                generate_username(
                    request.json.get("firstName") + " " + request.json.get("lastName")
                ),
                request.json.get("firstName").title(),
                request.json.get("lastName").title(),
                request.json.get("email").lower(),
                hash_password(request.json.get("password")),
                get_country_from_ip(request.remote_addr),
                "USER",
                f"https://cdn.projectrexa.dedyn.io/projectrexa/user-content/avatars/default-avatar.png",
                "EMAIL",
                False,
                profileID,
            ),
        )

        SQL_DATABASE_CONNECTION.commit()

    except Exception as error:
        print(error)
        SQL_DATABASE_CONNECTION.rollback()
        return {
            "status": "error",
            "message": "Our internal services are facing some issues, please try again later",
        }, 500

    return {
        "status": "success",
        "message": "Account Created Successfully",
        "redirect": url_for("sign_in"),
    }, 200


@app.route("/api/v1/forgot-password", methods=["POST"])
def api_forgot_password():
    if (
        request.json.get("email") is None
        or request.json.get("reCaptchaResponse") is None
    ):
        return {
            "status": "error",
            "message": "The request is invalid or missing a required parameter",
        }, 400

    if not verify_recaptcha(request.json.get("reCaptchaResponse")):
        return {"status": "error", "message": "Invalid reCAPTCHA response"}, 400

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Users WHERE Email = %s", (request.json.get("email").lower(),)
    )

    user_data = SQL_DATABASE_CURSOR.fetchone()

    if user_data is None:
        return {
            "status": "error",
            "message": "No account has been registered with this email address",
        }, 400

    SQL_DATABASE_CURSOR.execute(
        "DELETE FROM Tokens WHERE TokenIssuedTo = %s AND TokenAuthority = %s",
        (request.json.get("email").lower(), "PASSWORD_RESET"),
    )

    PASSWORD_RESET_TOKEN = secrets.token_urlsafe(32)

    SQL_DATABASE_CURSOR.execute(
        "INSERT INTO Tokens (TokenValue, TokenIssuedTo, TokenAuthority, TokenUsed) VALUES (%s, %s, %s, %s)",
        (
            PASSWORD_RESET_TOKEN,
            request.json.get("email").lower(),
            "PASSWORD_RESET",
            False,
        ),
    )

    if not send_email(
        request.json.get("email").lower(),
        user_data[2] + " " + user_data[3],
        "user-password-reset",
        PASSWORD_RESET_TOKEN,
    ):
        return {
            "status": "error",
            "message": "Our internal services are facing some issues, please try again later",
        }, 500

    return {
        "status": "success",
        "message": "A password reset instructions has been sent to your email address",
        "redirect": url_for("sign_in"),
    }, 200


@app.route("/api/v1/reset-password", methods=["POST"])
def api_reset_password():
    if (
        request.json.get("password") is None
        or request.json.get("reCaptchaResponse") is None
        or request.json.get("token") is None
    ):
        return {
            "status": "error",
            "message": "The request is invalid or missing a required parameter",
        }, 400

    if not verify_recaptcha(request.json.get("reCaptchaResponse")):
        return {"status": "error", "message": "Invalid reCAPTCHA response"}, 400

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Tokens WHERE TokenValue = %s AND TokenAuthority = %s AND TokenUsed = %s",
        (request.json.get("token"), "PASSWORD_RESET", False),
    )

    token_data = SQL_DATABASE_CURSOR.fetchone()

    if token_data is None:
        return {
            "status": "error",
            "message": "The password reset link was invalid please make sure you copied the link correctly",
        }, 400

    if token_data[5] < (datetime.datetime.now() - datetime.timedelta(hours=24)):
        return {
            "status": "error",
            "message": "The password reset link has expired, please request a new link",
        }, 400

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Users WHERE Email = %s", (token_data[2],)
    )

    user_data = SQL_DATABASE_CURSOR.fetchone()

    if user_data is None:
        return {
            "status": "error",
            "message": "The password reset link was invalid please make sure you copied the link correctly",
        }, 400

    try:
        SQL_DATABASE_CURSOR.execute(
            "UPDATE Users SET PasswordHash = %s WHERE Email = %s",
            (hash_password(request.json.get("password")), token_data[2]),
        )

        SQL_DATABASE_CURSOR.execute(
            "DELETE FROM Tokens WHERE TokenValue = %s", (request.json.get("token"),)
        )

        SQL_DATABASE_CONNECTION.commit()

    except Exception as error:
        SQL_DATABASE_CURSOR.rollback()

        return {
            "status": "error",
            "message": "Our internal services are facing some issues, please try again later",
        }, 500

    return {
        "status": "success",
        "message": "The account password was reset successfully, please sign in with your new password",
        "redirect": url_for("sign_in"),
    }, 200


@app.route("/api/v1/verify-email", methods=["GET"])
def api_verify_email():
    if request.args.get("token") is None:
        return redirect(
            url_for(
                "sign_in",
                alert="The email verification link was invalid please make sure you copied the link correctly",
                alertType="info",
            )
        )

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Tokens WHERE TokenValue = %s AND TokenAuthority = %s AND TokenUsed = %s",
        (request.args.get("token"), "EMAIL_VERIFICATION", False),
    )

    token_data = SQL_DATABASE_CURSOR.fetchone()

    if token_data is None:
        return redirect(
            url_for(
                "sign_in",
                alert="The email verification link was invalid please make sure you copied the link correctly",
                alertType="info",
            )
        )

    if token_data[5] < (datetime.datetime.now() - datetime.timedelta(hours=24)):
        return redirect(
            url_for(
                "sign_in",
                alert="The email verification link has expired, please request a new link",
                alertType="info",
            )
        )

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Users WHERE Email = %s", (token_data[2],)
    )

    user_data = SQL_DATABASE_CURSOR.fetchone()

    if user_data is None:
        return redirect(
            url_for(
                "sign_in",
                alert="The email verification link was invalid please make sure you copied the link correctly",
                alertType="info",
            )
        )

    try:
        SQL_DATABASE_CURSOR.execute(
            "UPDATE Users SET EmailVerified = %s WHERE Email = %s",
            (True, token_data[2]),
        )

        SQL_DATABASE_CURSOR.execute(
            "DELETE FROM Tokens WHERE TokenValue = %s", (request.args.get("token"),)
        )

        SQL_DATABASE_CONNECTION.commit()

    except Exception as error:
        SQL_DATABASE_CURSOR.rollback()

        return redirect(
            url_for(
                "sign_in",
                alert="Our internal services are facing some issues, please try again later",
                alertType="danger",
            )
        )

    return redirect(
        url_for(
            "sign_in",
            alert="Your email address was verified successfully, please sign in to continue",
            alertType="success",
        )
    )


@app.route("/api/v1/resend-verification-email", methods=["POST"])
def api_resend_verification_email():
    if (
        request.json.get("email") is None
        or request.json.get("reCaptchaResponse") is None
    ):
        return {
            "status": "error",
            "message": "The request is invalid or missing a required parameter",
            "requestID": uuid.uuid4().hex,
        }, 400

    if not verify_recaptcha(request.json.get("reCaptchaResponse")):
        return {
            "status": "error",
            "message": "Invalid reCAPTCHA response",
            "requestID": uuid.uuid4().hex,
        }, 400

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Users WHERE Email = %s", (request.json.get("email").lower(),)
    )

    user_data = SQL_DATABASE_CURSOR.fetchone()

    if user_data is None:
        return {
            "status": "error",
            "message": "No account has been registered with this email address",
            "requestID": uuid.uuid4().hex,
        }, 400

    if user_data[15]:
        return {
            "status": "error",
            "message": "Email address is already verified",
            "requestID": uuid.uuid4().hex,
        }, 400

    SQL_DATABASE_CURSOR.execute(
        "DELETE FROM Tokens WHERE TokenIssuedTo = %s AND TokenAuthority = %s",
        (request.json.get("email").lower(), "EMAIL_VERIFICATION"),
    )

    EMAIL_VERIFICATION_TOKEN = secrets.token_urlsafe(32)

    SQL_DATABASE_CURSOR.execute(
        "INSERT INTO Tokens (TokenValue, TokenIssuedTo, TokenAuthority, TokenUsed) VALUES (%s, %s, %s, %s)",
        (
            EMAIL_VERIFICATION_TOKEN,
            request.json.get("email").lower(),
            "EMAIL_VERIFICATION",
            False,
        ),
    )

    if not send_email(
        request.json.get("email").lower(),
        user_data[2] + " " + user_data[3],
        "user-registration",
        EMAIL_VERIFICATION_TOKEN,
    ):
        return {
            "status": "error",
            "message": "Our internal services are facing some issues, please try again later",
            "requestID": uuid.uuid4().hex,
        }, 500

    return {
        "status": "success",
        "message": "The email verification instructions has been sent to your email address",
        "requestID": uuid.uuid4().hex,
    }, 200


@app.route("/api/v1/oauth/authenticate", methods=["GET"])
def api_oauth_authenticate():
    if (
        request.args.get("applicationID") is None
        or request.args.get("requestState") is None
        or request.args.get("redirectURI") is None
    ):
        return {
            "status": "error",
            "message": f"The oauth request failed due to missing parameter {request.args.get('applicationID') if request.args.get('applicationID') is None else request.args.get('requestState') if request.args.get('requestState') is None else request.args.get('redirectURI') if request.args.get('redirectURI') is None else ''}",
        }, 400

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Applications WHERE ApplicationClientID = %s",
        (request.args.get("applicationID"),),
    )

    application_data = SQL_DATABASE_CURSOR.fetchone()

    if application_data is None:
        return {
            "status": "error",
            "message": "The oauth request failed due to invalid application ID",
            "requestID": uuid.uuid4().hex,
        }, 400

    if g.user.session.get("loggedIn"):
        oauth_token = secrets.token_urlsafe(32)

        SQL_DATABASE_CURSOR.execute(
            "INSERT INTO ApplicationTokens (ApplicationID, TokenValue, TokenAuthorizedAccount) VALUES (%s, %s, %s)",
            (
                request.args.get("applicationID"),
                oauth_token,
                g.user.session.get("userID"),
            ),
        )

        return redirect(
            f"{application_data[3]}?code={oauth_token}&state={request.args.get('requestState')}"
        )

    else:
        g.user.set(
            "next",
            f"http://accounts.projectrexa.dedyn.io/api/v1/oauth/authenticate?applicationID={request.args.get('applicationID')}&requestState={request.args.get('requestState')}&redirectURI={request.args.get('redirectURI')}",
        )
        return redirect(url_for("sign_in"))


@app.route("/api/v1/oauth/user", methods=["POST"])
def api_oauth_user():
    request_data = request.get_json()

    if (
        request_data.get("token") is None
        or request_data.get("applicationID") is None
        or request_data.get("applicationSecret") is None
    ):
        return {
            "status": "error",
            "message": f"The oauth request failed due to missing parameter {request_data.get('token') if request_data.get('token') is None else request_data.get('applicationID') if request_data.get('applicationID') is None else request_data.get('applicationSecret') if request_data.get('applicationSecret') is None else ''}",
            "requestID": uuid.uuid4().hex,
        }, 400

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM Applications WHERE ApplicationClientID = %s AND ApplicationClientSecret = %s",
        (request_data.get("applicationID"), request_data.get("applicationSecret")),
    )

    application_data = SQL_DATABASE_CURSOR.fetchone()

    if application_data is None:
        return {
            "status": "error",
            "message": "The oauth request failed due to invalid application ID or application secret",
            "requestID": uuid.uuid4().hex,
        }, 400

    SQL_DATABASE_CURSOR.execute(
        "SELECT * FROM ApplicationTokens WHERE TokenValue = %s AND ApplicationID = %s",
        (request_data.get("token"), request_data.get("applicationID")),
    )

    token_data = SQL_DATABASE_CURSOR.fetchone()

    if token_data is None:
        return {
            "status": "error",
            "message": "The oauth request failed due to an invalid token",
            "requestID": uuid.uuid4().hex,
        }, 400

    if token_data[1] != request_data.get("applicationID"):
        return {
            "status": "error",
            "message": "The oauth request failed due to an invalid token",
            "requestID": uuid.uuid4().hex,
        }, 400

    if token_data[5] < (datetime.datetime.now() - datetime.timedelta(seconds=30)):
        SQL_DATABASE_CURSOR.execute(
            "DELETE FROM ApplicationTokens WHERE TokenValue = %s",
            (request_data.get("token"),),
        )

        SQL_DATABASE_CONNECTION.commit()

        return {
            "status": "error",
            "message": "The oauth request failed due to an expired token",
            "requestID": uuid.uuid4().hex,
        }, 400

    SQL_DATABASE_CURSOR.execute(
        "SELECT UserID, Username, FirstName, LastName, Email, AccountRole, ProfileImageURL FROM Users WHERE UserID = %s",
        (token_data[3],),
    )

    user_data = SQL_DATABASE_CURSOR.fetchone()

    if user_data is None:
        return (
            {
                "status": "error",
                "message": "The oauth request failed due to an invalid token",
                "requestID": uuid.uuid4().hex,
            },
        )

    SQL_DATABASE_CURSOR.execute(
        "DELETE FROM ApplicationTokens WHERE TokenValue = %s",
        (request_data.get("token"),),
    )

    SQL_DATABASE_CONNECTION.commit()

    return {
        "status": "success",
        "message": "The oauth request was successful",
        "user": {
            "userID": user_data[0],
            "userName": user_data[1],
            "firstName": user_data[2],
            "lastName": user_data[3],
            "email": user_data[4],
            "accountRole": user_data[5],
            "profileImageURL": user_data[6],
        },
        "requestID": uuid.uuid4().hex,
    }, 200


@app.route("/api/v1/ping", methods=["GET"])
def api_ping():
    return (
        jsonify(
            {"status": "success", "message": "Pong", "requestID": uuid.uuid4().hex}
        ),
        200,
    )


# Error Handlers


@app.errorhandler(404)
def error_404(error):
    return (
        jsonify(
            {
                "status": "error",
                "message": "The requested resource was not found",
                "requestID": uuid.uuid4().hex,
            }
        ),
        404,
    )


@app.errorhandler(405)
def error_405(error):
    return (
        jsonify(
            {
                "status": "error",
                "message": "The requested method is not allowed",
                "requestID": uuid.uuid4().hex,
            }
        ),
        405,
    )


@app.errorhandler(500)
def error_500(error):
    return (
        jsonify(
            {
                "status": "error",
                "message": "Our internal services are facing some issues, please try again later",
                "requestID": uuid.uuid4().hex,
            }
        ),
        500,
    )


if __name__ == "__main__":
    app.run(debug=CONFIG.DEBUG, port=5000)
