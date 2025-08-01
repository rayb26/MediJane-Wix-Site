from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
from sqlalchemy import LargeBinary
import hashlib

db = SQLAlchemy()
bcrypt = Bcrypt()

# do print(Fernet.generate_key()) to create your own key and paste in here
key = b'<0zJ1kVAKXZ7xeCclD5Opqkuj31vf5dm6CX0HJFENHwI=>'
f = Fernet(key)


class EncryptedMixin:
    _fernet = f

    @classmethod
    def __init_subclass__(cls):
        super().__init_subclass__()

        encrypted_fields = getattr(cls, "__encrypted_fields__", [])

        for field in encrypted_fields:
            setattr(cls, f"_{field}", db.Column(LargeBinary))

            def getter(self, fname=field):
                raw = getattr(self, f"_{fname}")
                if raw is None:
                    return None
                return self._fernet.decrypt(raw).decode()

            def setter(self, value, fname=field):
                if value is None:
                    setattr(self, f"_{fname}", None)
                else:
                    setattr(self, f"_{fname}",
                            self._fernet.encrypt(value.encode()))

            setattr(cls, field, property(getter, setter))


def hash_email(email: str) -> str:
    return hashlib.sha256(email.encode()).hexdigest()


class User(db.Model, EncryptedMixin):
    __tablename__ = 'users'

    __encrypted_fields__ = ['email', 'phone']

    username = db.Column(db.String(80), primary_key=True,
                         unique=True, nullable=False)
    email_hash = db.Column(db.String(64), unique=True,
                           nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    medical_histories = db.relationship(
        'MedicalHistoryModel', backref='user', cascade='all, delete-orphan')
    appointments = db.relationship(
        'Appointment', backref='user', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(
            password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class MedicalHistoryModel(db.Model, EncryptedMixin):
    __tablename__ = "medical_history"
    __encrypted_fields__ = [
        "first_name", "last_name", "birth_date", "gender", "weight",
        "height", "allergies", "medications", "conditions", "injuries",
        "reason_for_visit", "additional_comments"
    ]

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), db.ForeignKey(
        "users.username"), nullable=False)

    has_used_cannabis = db.Column(db.Boolean)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Appointment(db.Model, EncryptedMixin):
    __encrypted_fields__ = ['day', 'time', 'location', 'provider']

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), db.ForeignKey(
        "users.username"), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
