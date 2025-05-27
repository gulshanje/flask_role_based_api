from flask import request, jsonify
from models import User, db

def paginate_users(page, per_page):
    return User.query.paginate(page=page, per_page=per_page, error_out=False)

def filter_users(**filters):
    query = User.query
    
    if 'name' in filters:
        query = query.filter(User.name.ilike(f"%{filters['name']}%"))
    if 'email' in filters:
        query = query.filter(User.email.ilike(f"%{filters['email']}%"))
    if 'country' in filters:
        query = query.filter(User.country.ilike(f"%{filters['country']}%"))
    if 'role' in filters:
        role_map = {v: k for k, v in User.ROLES.items()}
        role_value = [k for k, v in role_map.items() if v == filters['role']]
        if role_value:
            query = query.filter(User.role == role_value[0])
    
    return query

def validate_user_data(data, partial=False):
    errors = {}
    
    if not partial or 'email' in data:
        if not data.get('email'):
            errors['email'] = 'Email is required'
        elif User.query.filter_by(email=data['email']).first():
            errors['email'] = 'Email already exists'
    
    if not partial or 'name' in data:
        if not data.get('name'):
            errors['name'] = 'Name is required'
    
    if not partial or 'password' in data:
        if not partial and not data.get('password'):
            errors['password'] = 'Password is required'
    
    if errors:
        return False, errors
    
    return True, None