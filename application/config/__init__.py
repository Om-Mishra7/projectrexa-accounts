import os
import redis
import dotenv
import pymongo

dotenv.load_dotenv()

class Config:

    def __init__(self):

        self.application_info = {
            'name': 'ProjectRexa Single Sign-On Service',
            'version': '3.0.1',
            'description': 'Single Sign-On service for ProjectRexa and its services',
        }

        self.authour_info = {
            'name': 'Om Mishra',
            'website': 'https://om-mishra.com',
            'email': 'contact[at]om-mishra[dot]com',
            'github': 'https://github.com/Om-Mishra7',
            'linkedin': 'https://www.linkedin.com/in/om-mishra7',
        }

        self.enviroment_info = {
            'name': os.getenv('AAPLICATION_ENVIRONMENT', 'production'),
            'debug': os.getenv('DEBUG', False),
            'host': os.getenv('HOST', '0.0.0.0'),
            'port': os.getenv('PORT', 80),
        }

        if os.getenv('SECRET_KEY') is None:
            raise ValueError('Configuration error: Required environment variable `SECRET_KEY` is not set')
        
        self.secret_key = os.getenv('SECRET_KEY')

        if os.getenv('MONGODB_URI') is None:
            raise ValueError('Configuration error: Required environment variable `MONGODB_URI` is not set')

        try:
            database_connection = pymongo.MongoClient(
                os.getenv('MONGODB_URI')
            )
        
        except pymongo.errors.ConnectionFailure:
            raise ValueError('Configuration error: An error occurred while connecting to the MongoDB database')
        
        self.database_cursor = database_connection["projectrexa-sso"]
        
        if os.getenv('REDIS_URI') is None:
            raise ValueError('Configuration error: Required environment variable `REDIS_URI` is not set')
        

        try:
            self.redis_connection = redis.Redis.from_url(
                os.getenv('REDIS_URI')
            )

        except redis.exceptions.ConnectionError:
            raise ValueError('Configuration error: An error occurred while connecting to the Redis database')
        
    
        if os.getenv('RESEND_API_KEY') is None:
            raise ValueError('Configuration error: Required environment variable `RESEND_API_KEY` is not set')
        
        self.resend_api_key = os.getenv('RESEND_API_KEY')
    
        

