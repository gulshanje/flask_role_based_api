from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import bcrypt

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    ROLES = {
        'admin': 0,
        'teacher': 1,
        'student': 2
    }
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(db.Date)
    country = db.Column(db.String(80))
    image = db.Column(db.String(255))
    role = db.Column(db.Integer, nullable=False, default=ROLES['student'])
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, email, name, password, date_of_birth=None, country=None, image=None, role='student'):
        self.email = email
        self.name = name
        self.set_password(password)
        self.date_of_birth = date_of_birth
        self.country = country
        self.image = image
        self.role = self.ROLES.get(role, self.ROLES['student'])
    
    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
    
    def is_admin(self):
        return self.role == self.ROLES['admin']
    
    def is_teacher(self):
        return self.role == self.ROLES['teacher']
    
    def is_student(self):
        return self.role == self.ROLES['student']
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'date_of_birth': self.date_of_birth.isoformat() if self.date_of_birth else None,
            'country': self.country,
            'image': self.image,
            'role': next((k for k, v in self.ROLES.items() if v == self.role), 'student'),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

    def get_role_name(self):
        return next((k for k, v in self.ROLES.items() if v == self.role), 'student')
    
class TokenBlocklist(db.Model):
    __tablename__ = 'token_blocklist'

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)

    def __init__(self, jti):
        self.jti = jti
        self.created_at = datetime.utcnow()