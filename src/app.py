from flask import Flask, request, jsonify
from flask_cors import CORS
from models.utils.user_model import db, bcrypt, User
from config import Config

from dotenv import load_dotenv


app = Flask(__name__)
load_dotenv()
app.config.from_object(Config)
CORS(app)

db.init_app(app)
bcrypt.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists'}), 409

    user = User(email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid email or password'}), 401

# Optional: logout could be handled on frontend for simple apps

if __name__ == '__main__':
    app.run(debug=True, port=5001)
