import streamlit as st

# In-memory user and data store
users = {
    "admin": "admin123"
}

stored_data = {}  # Format: { username: {"encrypted_text": ..., "passkey": ...} }
failed_attempts = {}

def authenticate_user(username, password):
    return users.get(username) == password

def register_user(username, password):
    if username in users:
        return False
    users[username] = password
    return True

def increment_attempts(username):
    failed_attempts[username] = failed_attempts.get(username, 0) + 1

def reset_attempts(username):
    failed_attempts[username] = 0

def is_locked_out(username):
    return failed_attempts.get(username, 0) >= 3
