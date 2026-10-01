"""Auth module - handles user authentication"""
import os
import json
import hashlib
import secrets
from functools import wraps

USERS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'users.json')


def _load_users():
    """Load users from JSON file"""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}


def _save_users(users):
    """Save users to JSON file"""
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)


def _hash_password(password, salt=None):
    """Hash a password with salt"""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{hashed.hex()}"


def _verify_password(password, stored_hash):
    """Verify a password against stored hash"""
    salt, hash_hex = stored_hash.split(':')
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() == hash_hex


def register_user(username, password):
    """Register a new user"""
    users = _load_users()
    if username in users:
        return {'success': False, 'message': 'Username already exists'}

    users[username] = {
        'password': _hash_password(password),
        'created_at': __import__('datetime').datetime.now().isoformat(),
    }
    _save_users(users)
    return {'success': True, 'message': 'User registered successfully'}


def authenticate_user(username, password):
    """Authenticate a user"""
    users = _load_users()
    if username not in users:
        return {'success': False, 'message': 'Invalid username or password'}

    if _verify_password(password, users[username]['password']):
        token = secrets.token_hex(32)
        users[username]['token'] = token
        _save_users(users)
        return {'success': True, 'token': token, 'username': username}

    return {'success': False, 'message': 'Invalid username or password'}


def validate_token(token):
    """Validate an auth token"""
    if not token:
        return None
    users = _load_users()
    for username, data in users.items():
        if data.get('token') == token:
            return username
    return None


def create_default_user():
    """Create a default admin user if no users exist"""
    users = _load_users()
    if not users:
        result = register_user('admin', 'admin123')
        if result['success']:
            return 'Default user created: admin / admin123'
    return None
