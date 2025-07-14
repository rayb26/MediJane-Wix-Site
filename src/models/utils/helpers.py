
import jwt
from flask import request, jsonify
from functools import wraps
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token

JWT_SECRET = 'your-secret-key'


def get_username_from_token(auth_header):
    if not auth_header or not auth_header.startswith('Bearer '):
        print("test ")
        return None

    token = auth_header.split(" ")[1]
    print("token " + token)
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        print("decod " + str(decoded))
        return decoded.get("username")
    except jwt.ExpiredSignatureError:
        print("test")
        return None
    except jwt.InvalidTokenError:
        print("test 2")

        return None


def get_username_from_token(request):
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
        return username 
    except: 
        return jsonify({'message': 'Error receiving request'}, 400)