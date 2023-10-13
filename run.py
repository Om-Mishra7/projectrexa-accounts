from app import app
from werkzeug.serving import WSGIRequestHandler
from app.config import get_config

config = get_config()

if __name__ == '__main__':
    WSGIRequestHandler.protocol_version = "HTTP/1.1"
    app.run()
