from functools import wraps
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask import Flask, request, jsonify
from flask_cors import CORS
from models.utils.user_model import db, bcrypt, User
from config import Config
from models.utils.medical_history import MedicalHistory

from dotenv import load_dotenv

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'my_secret_key'
jwt = JWTManager(app)
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
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    phone = data.get('phone')

    if not all([username, email, password, phone]):
        return jsonify({'message': 'All fields are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User with this email already exists'}), 409

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User with this username already exists'}), 409

    user = User(username=username, email=email, phone=phone)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    print("user is " + str(user))
    if user and user.check_password(password):
        access_token = create_access_token(
            identity={'username': user.username})
        return jsonify({'token': access_token}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401


@app.route('/api/patient-history', methods=['POST'])
def submit_medical_history():
    data = request.get_json()

    # user = User.query.filter_by(username=current_user).first()
    # if not user:
    #     return jsonify({'message': 'User not found'}), 404

    try:
        history_record = MedicalHistory(
            user_id=user.id,
            first_name=data.get('firstName'),
            last_name=data.get('lastName'),
            birth_date=data.get('dob'),
            gender=data.get('gender'),
            weight=data.get('weight'),
            height=data.get('height'),
            allergies=data.get('allergies'),
            medications=data.get('medications'),
            conditions=data.get('conditions'),
            injuries=data.get('injuries')
            has_used_cannabis=data.get('cannabisUse') == 'Yes',
            reason_for_visit=data.get('reason'),
            additional_comments=data.get('comments'),
        )

        db.session.add(history_record)
        db.session.commit()
        return jsonify({'message': 'Medical history submitted successfully'}), 201

    except Exception as e:
        print('Error:', e)
        return jsonify({'message': 'Failed to save medical history'}), 400


@app.route('/medical-history/<username>', methods=['GET'])
def get_medical_history(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    history_records = MedicalHistory.query.filter_by(user_id=user.id).all()

    if not history_records:
        return jsonify({'message': 'No medical history found'}), 404

    history_data = []
    for record in history_records:
        history_data.append({
            'id': record.id,
            'first_name': record.first_name,
            'last_name': record.last_name,
            'birth_date': record.birth_date,
            'gender': record.gender,
            'weight': record.weight,
            'height': record.height,
            'allergies': record.allergies,
            'medications': record.medications,
            'conditions': record.conditions,
            'injuries': record.injuries,
            'has_used_cannabis': record.has_used_cannabis,
            'reason_for_visit': record.reason_for_visit,
            'additional_comments': record.additional_comments,
            'created_at': record.created_at.isoformat()
        })

    return jsonify({'medical_history': history_data}), 200


@app.route('/medical-history/<username>', methods=['PUT'])
def update_latest_medical_history(username):
    data = request.get_json()

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    history_entry = MedicalHistory.query.filter_by(user_id=user.id) \
                                        .order_by(MedicalHistory.created_at.desc()) \
                                        .first()
    if not history_entry:
        return jsonify({'message': 'No medical history to update'}), 404

    for field in [
        'first_name', 'last_name', 'birth_date', 'gender', 'weight', 'height',
        'allergies', 'medications', 'conditions', 'injuries',
        'has_used_cannabis', 'reason_for_visit', 'additional_comments'
    ]:
        if field in data:
            setattr(history_entry, field, data[field])

    db.session.commit()

    return jsonify({'message': 'Medical history updated successfully'}), 200


def role_required(required_role):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorated(*args, **kwargs):
            identity = get_jwt_identity()
            if identity['role'] != required_role:
                return jsonify({'message': 'Access forbidden: insufficient permissions'}), 403
            return fn(*args, **kwargs)
        return decorated
    return wrapper


if __name__ == '__main__':
    app.run(debug=True, port=5001)
