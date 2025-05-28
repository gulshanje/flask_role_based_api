import json
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, get_jwt, jwt_required, get_jwt_identity, verify_jwt_in_request
from datetime import datetime
from models import TokenBlocklist, User, db
from auth import admin_required, decode_token_if_valid, get_current_user, teacher_required, student_required, create_token
from utils import paginate_users, filter_users, validate_user_data
from config import Config
from flask_migrate import Migrate
import os
from auth import jwt

app = Flask(__name__)
CORS(app, resources={
    r"/login": {
        "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
        "methods": ["POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    },
     r"/users/*": {
        "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
        "methods": ["GET", "POST", "DELETE", "PUT" "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type"],
        "supports_credentials": True,
        "expose_headers": ["Authorization"]  
    }
})
# CORS(app, resources={
#      r"/login": {
#         "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
#         "methods": ["POST", "OPTIONS"],
#         "allow_headers": ["Content-Type"]
#     }
#     r"/users/*": {"origins": "http://localhost:3000"},
#     r"/logout": {"origins": "http://localhost:3000"}
# })
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
jwt.init_app(app)  # This must come after db initialization

jwt = JWTManager(app)
migrate = Migrate(app, db)
migrate.init_app(app, db)

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'message': 'Token has expired',
        'error': 'token_expired'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'message': 'Invalid token',
        'error': str(error)
    }), 422

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'message': 'Authorization token is missing',
        'error': str(error)
    }), 401

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
    return response
    
@app.cli.command('init-db')
def init_db():
    """Initialize the database."""
    with app.app_context():
        # Drop all tables
        db.drop_all()
        
        # Create all tables
        db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(email='admin@example.com').first():
            admin = User(
                email='admin@example.com',
                name='Admin',
                password='admin123',
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("Database initialized with admin user.")
        else:
            print("Database already initialized.")

@app.before_request
def before_request():
    print("Headers:", request.headers)
    print("Token:", request.headers.get('Authorization'))
    try:
        if request.headers.get('Authorization'):
            token = request.headers['Authorization'].split()[1]
            print("Token contents:", get_jwt_identity())
    except Exception as e:
        print("Token error:", str(e))

@app.route('/')
def home():
    # In your endpoint after @jwt_required
    # user_data = decode_token_if_valid(request.headers.get('Authorization'))
    # print(user_data)
    # return jsonify({'message': 'Role Based API', 'user_data': user_data})
    return render_template('home.html')

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    try:
        # Get the complete token claims
        claims = get_jwt()
        
        # Verify required claims exist
        if 'sub' not in claims:
            return jsonify({"error": "Missing subject claim"}), 422
            
        # Get user info from claims
        user_info = {
            'id': claims['sub'],
            'name': claims.get('name'),
            'email': claims.get('email'),
            'role': claims.get('role')
        }
        
        return jsonify(user_info), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/debug/token', methods=['POST'])
def debug_token():
    from flask_jwt_extended import decode_token
    try:
        token = request.json.get('token')
        decoded = decode_token(token)
        print(decoded['claims']['role'])
        return jsonify(decoded), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Email and password required'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    access_token = create_token(user)
    response = jsonify({
        'access_token': access_token,
        'user': user.to_dict()
    })
    
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response


@app.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    try:
        jti = get_jwt()['jti']
        now = datetime.utcnow()
        
        # Add token to blocklist
        db.session.add(TokenBlocklist(jti=jti))
        db.session.commit()
        
        return jsonify({
            "message": "Successfully logged out",
            "logout_time": now.isoformat()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    try:
        # Get current user claims
        claims = get_jwt()
        
        # Verify admin access
        if claims.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Query users with pagination
        users = User.query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Prepare response
        response = {
            'users': [user.to_dict() for user in users.items],
            'total': users.total,
            'pages': users.pages,
            'current_page': users.page
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/protected')
@jwt_required()
def protected():
    user_data = get_current_user()
    if not user_data:
        return jsonify({"message": "Invalid token"}), 401
    return jsonify(logged_in_as=user_data), 200

@app.route('/users/<int:user_id>', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_user(user_id):
    if request.method == 'OPTIONS':
        return {}, 200
    current_user = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    
    # Check permissions
    if current_user['role'] == User.ROLES['teacher'] and user.role not in [User.ROLES['teacher'], User.ROLES['student']]:
        return jsonify({'message': 'Unauthorized'}), 403
    elif current_user['role'] == User.ROLES['student'] and user.id != current_user['id']:
        return jsonify({'message': 'Unauthorized'}), 403
    
    return jsonify(user.to_dict())

@app.route('/users', methods=['POST'])
@admin_required
def create_user():
    data = request.get_json()
    
    valid, errors = validate_user_data(data)
    if not valid:
        return jsonify({'errors': errors}), 400
    
    try:
        user = User(
            email=data['email'],
            name=data['name'],
            password=data['password'],
            date_of_birth=datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date() if 'date_of_birth' in data else None,
            country=data.get('country'),
            image=data.get('image'),
            role=data.get('role', 'student')
        )
        db.session.add(user)
        db.session.commit()
        
        return jsonify(user.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/users/id/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_by_id(user_id):
    try:
        current_user = get_jwt()
        
        # Admin can access any user
        if current_user.get('role') in ['admin', 0]:
            user = User.query.get_or_404(user_id)
            return jsonify(user.to_dict())
        
        # Teachers can access themselves and students
        elif current_user.get('role') in ['teacher', 1]:
            requested_user = User.query.get_or_404(user_id)
            if requested_user.role in [User.ROLES['teacher'], User.ROLES['student']]:
                return jsonify(requested_user.to_dict())
            return jsonify({"message": "Unauthorized access"}), 403
        
        # Students can only access themselves
        elif current_user.get('id') == user_id:
            user = User.query.get_or_404(user_id)
            return jsonify(user.to_dict())
        
        return jsonify({"message": "Unauthorized access"}), 403

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/users/name/<string:name>', methods=['GET'])
@jwt_required()
def get_user_by_name(name):
    try:
        current_user = get_jwt()
        users = User.query.filter(User.name.ilike(f'%{name}%')).all()
        
        # Admin sees all matching users
        if current_user.get('role') in ['admin', 0]:
            return jsonify([user.to_dict() for user in users])
        
        # Teachers see teachers and students
        elif current_user.get('role') in ['teacher', 1]:
            filtered_users = [u for u in users if u.role in [
                User.ROLES['teacher'], 
                User.ROLES['student']
            ]
            ]
            return jsonify([user.to_dict() for user in filtered_users])
        
        # Students see only themselves
        else:
            filtered_users = [u for u in users if u.id == current_user.get('id')]
            return jsonify([user.to_dict() for user in filtered_users])

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    current_user = get_jwt()
    user = User.query.get_or_404(user_id)
    
    # Check permissions
    if current_user.get('role') in ['teacher', 1] and current_user.get('role') in ['admin', 0]:
        return jsonify({'message': 'Unauthorized'}), 403
    elif current_user.get('role') in ['student', 2] and user.id != current_user['id']:
        return jsonify({'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    
    # Validate data
    valid, errors = validate_user_data(data, partial=True)
    if not valid:
        return jsonify({'errors': errors}), 400
    
    try:
        if 'email' in data:
            user.email = data['email']
        if 'name' in data:
            user.name = data['name']
        if 'password' in data:
            user.set_password(data['password'])
        if 'date_of_birth' in data:
            user.date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date()
        if 'country' in data:
            user.country = data['country']
        if 'image' in data:
            user.image = data['image']
        if 'role' in data and current_user['role'] == User.ROLES['admin']:
            user.role = User.ROLES.get(data['role'], user.role)
        
        db.session.commit()
        
        return jsonify(user.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/users/<int:user_id>', methods=['PATCH'])
@jwt_required()
def partial_update_user(user_id):
    return update_user(user_id)

@app.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    try:
        claims = get_jwt()
        
        # Check admin access with all possible role representations
        if claims.get('role') not in ['admin', 0, User.ROLES['admin']]:
            return jsonify({"message": "Admin access required"}), 403
        
        # Prevent self-deletion
        if user_id == claims.get('sub'):
            return jsonify({"message": "Cannot delete yourself"}), 400
            
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({"message": "User deleted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 500

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    user = User.query.get(current_user['id'])
    access_token = create_access_token(identity=current_user)
    return jsonify({'access_token': access_token, 'user': user.to_dict()})

# @app.route('/debug-token', methods=['POST'])
# def debug_token():
#     try:
#         token = request.json.get('token')
#         if not token:
#             return jsonify({"error": "No token provided"}), 400
            
#         # Manual verification
#         verify_jwt_in_request()
#         claims = get_jwt_identity()
#         return jsonify({"claims": claims}), 200
        
#     except Exception as e:
#         return jsonify({
#             "error": str(e),
#             "message": "Token verification failed"
#         }), 422
    
if __name__ == '__main__':
    # Check database connection
    try:
        with app.app_context():
            db.engine.connect()
            print("Database connection successful")
            admin = User.query.filter_by(email='admin@example.com').first()
            print(admin.name) 
    except Exception as e:
        print(f"Database connection failed: {str(e)}")
        exit(1)
    # token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0ODE4OTkzNCwianRpIjoiYTZhNTY3ZTEtMmNiMS00NWVmLWIxNGEtNzA5YjZlYmZlZmYxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6eyJpZCI6MSwiZW1haWwiOiJhZG1pbkBleGFtcGxlLmNvbSIsInJvbGUiOjAsIm5hbWUiOiJBZG1pbiJ9LCJuYmYiOjE3NDgxODk5MzQsImNzcmYiOiI1ZTNjNjUwNy1lNjVmLTQ3Y2YtOGFiNC0zOWNlYWUxODA5ZGQiLCJleHAiOjE3NDgyMDA3MzR9.TeVgrvGSDhC7sWp1CBRoAVx7BJmFWhijDELB1hX2Zog"
    # decoded = jwt.decode(token, options={"verify_signature": False})
    # print(decoded)
    
    app.run(debug=True)