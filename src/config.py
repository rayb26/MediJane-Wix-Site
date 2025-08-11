# In your config.py or app configuration
import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "lilly")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://sabrinah:lilly@localhost:5432/db_sabrina"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False