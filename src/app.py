from functools import wraps
import stripe, os
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token, get_jwt
from flask import Flask, request, jsonify
from flask_cors import CORS
# from models.utils.user_model import db, bcrypt, User
from config import Config
from models.utils.medical_history import MedicalHistory
from models.utils.helpers import get_username_from_token, get_username_from_token
from flask_jwt_extended.exceptions import JWTDecodeError
from models.utils.models import User, db, bcrypt, MedicalHistoryModel, Appointment
from werkzeug.security import check_password_hash, generate_password_hash
from models.utils.models import hash_email
from dotenv import load_dotenv

app = Flask(__name__)

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")  # Stripe secret key stored in .env
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

    email_h = hash_email(email)

    print("email h " + str(email_h))

    if User.query.filter_by(email_hash=email_h).first():
        return jsonify({'message': 'User with this email already exists'}), 409

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User with this username already exists'}), 409

    user = User(
        username=username,
        email=email,          # encrypted transparently
        email_hash=email_h,   # plain hash for lookups
        phone=phone,          # encrypted transparently
        role="user"
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/change-password', methods=['POST'])
@jwt_required
def change_password():
    data = request.get_json()
    new_password = data.get('newPassword')
    username = data.get("username")

    if not new_password:
        return jsonify({'message': 'New password is required'}), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    user.set_password(new_password)
    db.session.commit()

    return jsonify({'message': 'Password changed successfully'}), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        access_token = create_access_token(
            identity=user.username,
            additional_claims={"role": user.role})

        return jsonify({'token': access_token}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401


@app.route('/book-appointment', methods=['POST'])
def book_appointment():
    data = request.get_json()

    username = data.get('username')
    day = data.get('day')
    time = data.get('time')
    location = data.get('location')
    provider = data.get('provider')

    if not username:
        return jsonify({'error': 'Missing username'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    appointment = Appointment(
        user_id=user.username,
        day=day,
        time=time,
        location=location,
        provider=provider
    )

    db.session.add(appointment)
    db.session.commit()

    return jsonify({'message': 'Appointment booked successfully'}), 200


@app.route('/appointment/<username>', methods=['GET'])
def get_appointment(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    appointment = Appointment.query.filter_by(
        user_id=user.username
    ).order_by(Appointment.created_at.desc()).first()

    if not appointment:
        return jsonify({'message': 'No appointment found'}), 404

    return jsonify({
        'appointment': {
            'day': appointment.day,
            'time': appointment.time,
            'location': appointment.location,
            'provider': appointment.provider
        }
    }), 200


@app.route('/medical-history', methods=['POST'])
def submit_medical_history():
    data = request.get_json()
    print("data is " + str(data))
    auth_header = request.headers.get('Authorization', None)
    if not auth_header:
        return jsonify({'message': 'Missing authorization header'}), 401

    try:
        token = auth_header.split()[1]
        decoded_token = decode_token(token)
        identity = decoded_token.get('sub')

        if isinstance(identity, dict):
            username = identity.get('username')
        else:
            username = identity

        if not username:
            return jsonify({'message': 'Invalid token: no username found'}), 401

        medical_history = MedicalHistory(data)

        medical_history = MedicalHistoryModel(
            user_id=username,
            first_name=medical_history.first_name,
            last_name=medical_history.last_name,
            birth_date=medical_history.birth_date,
            gender=medical_history.gender,
            weight=medical_history.weight,
            height=medical_history.height,
            allergies=medical_history.allergies,
            medications=medical_history.medications,
            conditions=medical_history.conditions,
            injuries=medical_history.injuries,
            has_used_cannabis=(medical_history.has_used_cannabis == 'Yes'),
            reason_for_visit=medical_history.reason_for_visit,
            additional_comments=medical_history.additional_comments
        )
        db.session.add(medical_history)
        db.session.commit()

        return jsonify({'message': 'Successfully Created Medical History'}), 200

    except JWTDecodeError as e:
        return jsonify({'message': 'Invalid token'}), 401
    except Exception as e:
        print("execption " + str(e))
        return jsonify({'message': 'Error processing token'}), 400


@app.route('/medical-history/<username>', methods=['GET'])
def get_medical_history(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    history_records = MedicalHistoryModel.query.filter_by(
        user_id=user.username).all()

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


@app.route('/cancel-appointment', methods=['DELETE'])
def cancel_appointment():
    data = request.get_json()

    username = data.get("username")
    if not username:
        return jsonify({'message': 'User not found'}), 404

    user = User.query.filter_by(username=username).first()

    appointment = Appointment.query.filter_by(user_id=user.username).first()

    if not appointment:
        return jsonify({'message': 'No appointment to cancel'}), 404

    db.session.delete(appointment)
    db.session.commit()

    return jsonify({'message': 'Appointment cancelled successfully'}), 200


@app.route('/delete-account/<username>', methods=['DELETE'])
def delete_account(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User does not exist'}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User account deleted successfully'}), 200


@app.route('/update-contact-info/<username>', methods=['PUT'])
def update_contact_info(username):
    data = request.get_json()

    new_email = data.get('email')
    new_phone = data.get('phone')

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if new_email:
        email_h = hash_email(new_email)
        if User.query.filter_by(email_hash=email_h).first():
            return jsonify({'message': 'Email already in use'}), 409
        user.email = new_email
        user.email_hash = email_h  # update hash too

    if new_phone:
        user.phone = new_phone

    db.session.commit()

    return jsonify({'message': 'Contact information updated successfully'})


@app.route('/medical-history/<username>', methods=['PUT'])
def update_latest_medical_history(username):
    data = request.get_json()

    user = User.query.filter_by(username=username).first()
    print("user " + str(user))
    if not user:
        return jsonify({'message': 'User not found'}), 404

    history_entry = MedicalHistoryModel.query.filter_by(user_id=user.username) \
                                             .order_by(MedicalHistoryModel.created_at.desc()) \
                                             .first()

    print("history_entry " + str(history_entry))
    if not history_entry:
        return jsonify({'message': 'No medical history to update'}), 404

    data = request.get_json()

    field_map = {
        'firstName': 'first_name',
        'lastName': 'last_name',
        'dob': 'birth_date',
        'gender': 'gender',
        'weight': 'weight',
        'height': 'height',
        'allergies': 'allergies',
        'medications': 'medications',
        'conditions': 'conditions',
        'injuries': 'injuries',
        'cannabisUse': 'has_used_cannabis',
        'reason': 'reason_for_visit',
        'comments': 'additional_comments'
    }

    for key, model_field in field_map.items():
        if key in data:
            value = data[key]
            if key == 'cannabisUse':
                value = value == 'Yes'
            setattr(history_entry, model_field, value)

    db.session.commit()
    return jsonify({'message': 'Medical history updated successfully'}), 200


@app.route('/')
@app.route('/admin/patient-appointments', methods=['GET'])
@jwt_required()
def get_all_appointments():
    identity = get_jwt_identity()
    claims = get_jwt()
    print("Identity:", identity)
    print("Claims:", claims)

    if claims.get('role') != 'admin':
        return jsonify({'message': 'Admins only'}), 403

    appointments = Appointment.query.all()
    print(f"Found {len(appointments)} appointments")

    results = []
    for appt in appointments:
        user = User.query.filter_by(username=appt.user_id).first()
        if not user:
            print(f"No user found for appointment user_id: {appt.user_id}")
            continue
        results.append({
            'patient_id': user.username,
            'username': user.username,
            'date': appt.day,
            'time': appt.time,
        })

    print("Results to return:", results)
    return jsonify({'appointments': results}), 200



@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    data = request.get_json()

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price_data': {
                        'currency': 'usd',
                        'unit_amount': 5000,  # $50.00 in cents
                        'product_data': {
                            'name': 'Consultation Appointment',
                            'description': f"{data['day']} at {data['time']} with {data['provider']}"
                        },
                    },
                    'quantity': 1,
                }
            ],
            mode='payment',
            success_url='http://localhost:3000/success', 
            cancel_url='http://localhost:3000/cancel',    
        )

        return jsonify({'url': checkout_session.url})
    
    except Exception as e:
        print(f"Stripe error: {e}")
        return jsonify(error=str(e)), 500

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


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        username = request.get_json().get("username")
        if not username:
            return jsonify({"message": "unable to parse request"}, 400)
        user = User.query.filter_by(username=username).first()

        if not user or user.role != 'admin':
            return jsonify({'message': 'Admins only!'}), 403

        return fn(*args, **kwargs)
    return wrapper


if __name__ == '__main__':
    # If you want to do a db migration, the easist thing to do is uncomment the follwing
    #with app.app_context():
    #    db.drop_all()
    #     db.create_all()
    #     print("done")
    app.run(debug=True, port=5001)
