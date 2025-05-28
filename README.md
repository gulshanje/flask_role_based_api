# Flask JWT Authentication API

A comprehensive Flask application with JWT authentication that can be deployed on PythonAnywhere.

## Features

- User authentication with JWT (access and refresh tokens)
- Role-based access control (admin, teacher, student)
- CRUD operations for users
- Token refresh functionality
- Database connection testing
- CORS support
- Pagination and filtering for user lists

## Setup

1. Clone the repository
2. Create a virtual environment and activate it
3. Install dependencies: `pip install -r requirements.txt`
4. Set up your database configuration in `config.py`
5. Initialize the database: `flask initdb`
6. Run the application: `flask run`

## PythonAnywhere Deployment

1. Create a new PythonAnywhere account
2. Set up a MySQL database in the "Databases" tab
3. Update the `SQLALCHEMY_DATABASE_URI` in `config.py` with your PythonAnywhere MySQL credentials
4. Upload your files to PythonAnywhere
5. Create a new web app and configure it to use your WSGI file
6. Restart your web app

## API Endpoints

### Authentication
- `POST /login` - Login and get JWT tokens
- `POST /refresh` - Refresh access token
- `DELETE /logout` - Logout (invalidate token)

### Users
- `GET /users` - List all users (admin only)
- `POST /users` - Create a new user (admin only)
- `GET /users/<int:user_id>` - Get user details
- `PUT /users/<int:user_id>` - Update user
- `PATCH /users/<int:user_id>` - Partial update user
- `DELETE /users/<int:user_id>` - Delete user (admin only)
- `GET /users/id/<int:user_id>` - Get user by ID
- `GET /users/name/<string:name>` - Search users by name (admin only)

### Utility
- `GET /protected` - Test protected route
- `GET /test_db` - Test database connection

## CURL Examples

### Login

curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "admin123"}'

### Get Users (Admin)

curl -X GET http://localhost:5000/users \
-H "Authorization: Bearer YOUR_ACCESS_TOKEN"