import os
from dotenv import load_dotenv

load_dotenv()

class Config():
    def __init__(self):
        self.secret_key = "secret_key"
        self.authority = ".projectrexa.dedyn.io"
        self.config_name = 'default'
        self.host = "0.0.0.0"
        self.port = 443
        self.redis_url = os.getenv("redis_url")
        self.mongoDB_url = os.getenv("mongoDB_url")
        self.secret_key = os.getenv("secret_key")
        self.debug = False
        self.recaptcha = True
        self.recaptcha_secret_key = os.getenv("recaptcha_secret_key")
        self.recaptcha_site_key = os.getenv("recaptcha_site_key")
        self.github_client_id = os.getenv("github_client_id")
        self.github_client_secret = os.getenv("github_client_secret")
        self.github_redirect_uri = "https://accounts.projectrexa.dedyn.io/callback/github"
        self.google_redirect_uri = "https://accounts.projectrexa.dedyn.io/callback/google"
        self.google_client_secret = os.getenv("google_client_secret")
        

class ProductionConfig(Config):
    def __init__(self):
        super().__init__()
        self.config_name = 'production'

class DevelopmentConfig(Config):
    def __init__(self):
        super().__init__()
        self.config_name = 'development'
        self.authority = "127.0.0.1:5000"
        self.debug = True
        self.recaptcha = True
        self.github_redirect_uri = "http://127.0.0.1:5000/callback/github"
        self.google_redirect_uri = "http://127.0.0.1:5000/callback/google"


class MaintananceConfig(Config):
    def __init__(self):
        super().__init__()
        self.config_name = 'maintanance'

def get_config():
    config = {
        'production': ProductionConfig(),
        'development': DevelopmentConfig(),
        'maintanance': MaintananceConfig(),
        'default': Config()
    }
    return config[os.getenv("config_name") or 'production']