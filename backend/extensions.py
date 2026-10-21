# This file creates the database and rate limiter instances
# We put them here to avoid circular imports between app.py and models
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
limiter = Limiter(key_func=get_remote_address)