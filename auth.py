from datetime import timedelta
from flask_jwt_extended import create_access_token, get_jwt, jwt_required, get_jwt_identity, verify_jwt_in_request
from functools import wraps
from flask import jsonify, request
from models import TokenBlocklist, User
from flask_jwt_extended import JWTManager

jwt = JWTManager()

def create_token(user):
    role_name = next((k for k, v in user.ROLES.items() if v == user.role), 'student')
    return create_access_token(
        identity=str(user.id),
        additional_claims={
            'email': user.email,
            'name': user.name,
            'role': next((k for k, v in user.ROLES.items() if v == user.role), 'student'),
            'role_id': user.role
        }
    )

def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        claims = get_jwt()
        if claims.get('role')not in ['admin', 0, User.ROLES['admin']]:
            return jsonify({'message': 'Admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper


        
def teacher_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        if current_user['role'] not in [User.ROLES['admin'], User.ROLES['teacher']]:
            return jsonify({'message': 'Teacher access required'}), 403
        return fn(*args, **kwargs)
    return wrapper

def student_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        if current_user['role'] not in [User.ROLES['admin'], User.ROLES['teacher'], User.ROLES['student']]:
            return jsonify({'message': 'Student access required'}), 403
        return fn(*args, **kwargs)
    return wrapper


from flask_jwt_extended import decode_token

def get_current_user():
    """Safe way to get current user after @jwt_required"""
    try:
        return get_jwt_identity()
    except Exception as e:
        print(f"Token decode error: {str(e)}")
        return None

def decode_token_if_valid(token):
    """For debugging only - not for normal use"""
    try:
        verify_jwt_in_request()
        return get_jwt_identity()
    except Exception as e:
        print(f"Decode error: {str(e)}")
        return None
    

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = TokenBlocklist.query.filter_by(jti=jti).first()
    return token is not None