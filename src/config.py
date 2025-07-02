import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "devsecretkey")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "load_password_from_env"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
