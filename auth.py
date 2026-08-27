# import json

# FILE = "users.json"

# def load_users():
#     with open(FILE, "r") as f:
#         return json.load(f)

# def save_users(data):
#     with open(FILE, "w") as f:
#         json.dump(data, f, indent=4)

# def register(username, password):
#     data = load_users()
    
#     for user in data["users"]:
#         if user["username"] == username:
#             return False  # user exists
    
#     data["users"].append({
#         "username": username,
#         "password": password
#     })
    
#     save_users(data)
#     return True

# def login(username, password):
#     data = load_users()
    
#     for user in data["users"]:
#         if user["username"] == username and user["password"] == password:
#             return True
    
#     return False


import json
import os
import hashlib
import secrets

FILE = "users.json"

# FIX: passwords are now stored as  "salt:sha256(salt+password)"
# so plain-text passwords never touch disk.

def _hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"

def _verify_password(stored, password):
    salt, _ = stored.split(":", 1)
    return stored == _hash_password(password, salt)

def load_users():
    if not os.path.exists(FILE):
        return {"users": []}
    with open(FILE, "r") as f:
        return json.load(f)

def save_users(data):
    with open(FILE, "w") as f:
        json.dump(data, f, indent=4)

def register(username, password):
    data = load_users()

    if any(u["username"] == username for u in data["users"]):
        return False

    data["users"].append({
        "username": username,
        "password": _hash_password(password),   # FIX: store hash, not plain text
    })
    save_users(data)
    return True

def login(username, password):
    data = load_users()
    for u in data["users"]:
        if u["username"] == username:
            stored = u.get("password", "")
            # Support both hashed (new) and legacy plain-text passwords
            if ":" in stored:
                return _verify_password(stored, password)
            # Legacy plain-text fallback — upgrade on successful login
            if stored == password:
                u["password"] = _hash_password(password)
                save_users(data)
                return True
    return False