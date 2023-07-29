import redis
import pymongo
import datetime
import time
from app.config import get_config

config = get_config()

def create_redis_database_connection(max_attempts=10, base_delay=5, attempt_number=1):
    while attempt_number <= max_attempts:

        try:
            redis_client = redis.Redis.from_url(config.redis_url, decode_responses=True)
            redis_client.ping()
            with open("log.log", "a") as f:
                f.write("{} | INFO - Connected to REDIS database\n\n".format(datetime.datetime.utcnow()))
            return redis_client

        except Exception as e:
            print("Redis Connection Error: ", e)
            time.sleep(base_delay * attempt_number**2)
            create_redis_database_connection(attempt_number=attempt_number+1)

    with open("log.log", "a") as f:
        f.write("{} | ERROR - Could not connect to REDIS database\n\n".format(datetime.datetime.utcnow()))
    raise Exception("Could not connect to database")


def create_mongoDB_database_connection(max_attempts=10, base_delay=5, attempt_number=1):
    while attempt_number <= max_attempts:

        try:
            mongo_client = pymongo.MongoClient(config.mongoDB_url)
            mongo_client.server_info()
            with open("log.log", "a") as f:
                f.write("{} | INFO - Connected to MONGO_DB database\n\n".format(datetime.datetime.utcnow()))
            return mongo_client

        except Exception as e:
            print("MongoDB Connection Error: ", e)
            time.sleep(base_delay * attempt_number**2)
            create_mongoDB_database_connection(attempt_number=attempt_number+1)

    with open("log.log", "a") as f:
        f.write("{} | ERROR - Could not connect to MONGO_DB database\n\n".format(datetime.datetime.utcnow()))
    raise Exception("Could not connect to database")