from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()


class User(db.Model):
    username = db.Column(db.String(80), primary_key=True,
                         unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False,
                     default='user')  # Add this line

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(
            password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class MedicalHistoryModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), db.ForeignKey(
        'user.username'), nullable=False)
    first_name = db.Column(db.String(100))

    last_name = db.Column(db.String(100))
    birth_date = db.Column(db.String(20))
    gender = db.Column(db.String(20))
    weight = db.Column(db.String(20))
    height = db.Column(db.String(20))
    allergies = db.Column(db.Text)
    medications = db.Column(db.Text)
    conditions = db.Column(db.Text)
    injuries = db.Column(db.Text)
    has_used_cannabis = db.Column(db.Boolean)
    reason_for_visit = db.Column(db.Text)
    additional_comments = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='medical_profiles')


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), db.ForeignKey(
        'user.username'), nullable=False)
    day = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    provider = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='appointments')
