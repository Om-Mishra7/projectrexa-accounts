from flask import Flask, request, make_response, redirect, url_for
from app.database import create_redis_database_connection, create_mongoDB_database_connection
from app.views import routes
from app.config import get_config
import datetime
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration


config = get_config()



sentry_sdk.init(
  dsn="https://7e94dc2fd5064ecebe6ea69c8097d8d1@o4504045228720128.ingest.sentry.io/4505602259943424",
  # Set tracesSampleRate to 1.0 to capture 100%
  # of transactions for performance monitoring.
  # We recommend adjusting this value in production
  traces_sample_rate=0.1,
)

app = Flask(__name__)
redis_client, mongoDB_client = create_redis_database_connection(), create_mongoDB_database_connection()

app.register_blueprint(routes)

# Function to log request data
@app.after_request
def logging(response):

    if response.status_code < 400:
        level = 'INFO'
    elif response.status_code >= 400 and response.status_code < 500:
        level = 'WARNING'
    else:
        level = 'ERROR'

    with open('log.log', 'a') as f:
        f.write('{} | {} | URL - {} | Status Code - {} | IP Address - {} | Cookies - {} | User Agent - {} | HTTP Method - {}\n\n'.format(
            datetime.datetime.now(),
            level,
            request.url,
            response.status_code,
            request.remote_addr,
            request.cookies,
            request.user_agent,
            request.method,
        ))
    return response

# Function to set headers
@app.after_request
def set_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Authority'] = config.authority
    return response
        

