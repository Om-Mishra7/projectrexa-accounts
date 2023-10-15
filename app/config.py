'''
This file contains the config classes for the server
'''
import os
from dotenv import load_dotenv

load_dotenv()


class Config():
    '''
    This is the base config class, all other configs inherit from this class
    '''

    def __init__(self):
        '''
        This is the base config class, all other configs inherit from this class
        '''
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
        self.sentry_dsn = os.getenv("sentry_dsn")
        self.tebi_access_key_id = os.getenv("TEBI_ACCESS_KEY_ID")
        self.tebi_secret_access_key = os.getenv("TEBI_SECRET_ACCESS_KEY")
        self.api_key = os.getenv("api_key")


class ProductionConfig(Config):
    '''
    This config is used when the server is running in production
    '''

    def __init__(self):
        '''
        This config is used when the server is running in production
        '''
        super().__init__()
        self.config_name = 'production'


class DevelopmentConfig(Config):
    '''
    This config is used when the server is running locally
    '''

    def __init__(self):
        '''
        This config is used when the server is running locally
        '''
        super().__init__()
        self.config_name = 'development'
        self.authority = "127.0.0.1:5000"
        self.debug = True
        self.recaptcha = True
        self.github_redirect_uri = "http://127.0.0.1:5000/callback/github"
        self.google_redirect_uri = "http://127.0.0.1:5000/callback/google"


class MaintananceConfig(Config):
    '''
    This config is used when the server is down for maintanance
    '''

    def __init__(self):
        '''
        This config is used when the server is down for maintanance
        '''
        super().__init__()
        self.config_name = 'maintanance'


def get_config():
    '''
    Returns the config class based on the environment variable config_name
    '''
    config = {
        'production': ProductionConfig(),
        'development': DevelopmentConfig(),
        'maintanance': MaintananceConfig(),
        'default': Config()
    }
    return config[os.getenv("config_name") or 'production']
