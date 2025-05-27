import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-here')
    JWT_TOKEN_LOCATION= ['headers', 'cookies'] 
    JWT_ACCESS_TOKEN_EXPIRES = 10800  # 3 hours in seconds
    JWT_IDENTITY_CLAIM = 'identity'  # Add this line
    JWT_IDENTITY_CLAIM = "sub"  # Standard JWT subject claim
    JWT_CLAIMS_IN_TOKEN = True  # Ensure claims are included
    JWT_ADDITIONAL_CLAIMS = ['email', 'name', 'role']  # Whitelist claims
    JWT_BLACKLIST_ENABLED = True  # Enable token blacklisting
    JWT_BLACKLIST_TOKEN_CHECKS = ['access']  # Enable blacklist for access tokens
    JWT_ACCESS_COOKIE_PATH='/'
    JWT_COOKIE_CSRF_PROTECT=False
    JWT_ACCESS_COOKIE_NAME='access_token_cookie'