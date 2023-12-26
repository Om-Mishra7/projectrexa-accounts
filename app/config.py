import os
from dotenv import load_dotenv


load_dotenv()


class CONFIG:
    
    if os.getenv("SERVER_ENVIRONMENT") == "DEVELOPMENT":
        SERVER_ENVIRONMENT = "DEVELOPMENT"
        DEBUG = True
        TESTING = True
        GITHUB_REDIRECT_URI = "http://127.0.0.1:5000" + os.getenv("GITHUB_REDIRECT_URI")
        GOOGLE_REDIRECT_URI = "http://127.0.0.1:5000" + os.getenv("GOOGLE_REDIRECT_URI")
        DISCORD_REDIRECT_URI = "http://127.0.0.1:5000" + os.getenv("DISCORD_REDIRECT_URI")
        REDDIT_REDIRECT_URI = "http://127.0.0.1:5000" + os.getenv("REDDIT_REDIRECT_URI")
        
        
        
    else:
        SERVER_ENVIRONMENT = "PRODUCTION"
        DEBUG = False
        TESTING = False
        GITHUB_REDIRECT_URI = "https://accounts.projectrexa.dedyn.io" + os.getenv("GITHUB_REDIRECT_URI")
        GOOGLE_REDIRECT_URI = "https://accounts.projectrexa.dedyn.io" + os.getenv("GOOGLE_REDIRECT_URI")
        DISCORD_REDIRECT_URI = "https://accounts.projectrexa.dedyn.io" + os.getenv("DISCORD_REDIRECT_URI")
        REDDIT_REDIRECT_URI = "https://accounts.projectrexa.dedyn.io" + os.getenv("REDDIT_REDIRECT_URI")
        
    APPLICATION_SECRET_KEY = os.getenv("APPLICATION_SECRET_KEY")
    
    ATHER_API_KEY = os.getenv("ATHER_API_KEY")
    
    PLANETSCALE_DATABASE = os.getenv("PLANETSCALE_DATABASE")
    PLANETSCALE_DATABASE_HOST = os.getenv("PLANETSCALE_DATABASE_HOST")
    PLANETSCALE_DATABASE_USERNAME = os.getenv("PLANETSCALE_DATABASE_USERNAME")
    PLANETSCALE_DATABASE_PASSWORD = os.getenv("PLANETSCALE_DATABASE_PASSWORD")
    
    REDIS_DATABASE_URL = os.getenv("REDIS_DATABASE_URL")
    
    RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
    RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
    
    AUTHENTICATION_METHODS = ["EMAIL", "GITHUB", "GOOGLE", "DISCORD", "REDDIT"]
    
    GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
    
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    
    DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
    DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
    
    TWITTER_CLIENT_ID = os.getenv("TWITTER_CLIENT_ID")
    TWITTER_CLIENT_SECRET = os.getenv("TWITTER_CLIENT_SECRET")
    
    REDDIT_CLIENT_ID = os.getenv("REDDIT_CLIENT_ID")
    REDDIT_CLIENT_SECRET = os.getenv("REDDIT_CLIENT_SECRET")

    
    

    
    
        