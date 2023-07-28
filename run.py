from app import app
from app.config import get_config

config = get_config()

if __name__ == '__main__':
    gunicorn_app = app()