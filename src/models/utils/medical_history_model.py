from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from models.utils.user_model import User

db = SQLAlchemy()
bcrypt = Bcrypt()


class MedicalHistoryModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

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
