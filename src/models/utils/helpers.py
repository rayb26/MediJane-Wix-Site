
import jwt
from flask import request, jsonify
from functools import wraps

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
