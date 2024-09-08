from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from app.auth import AuthHandler

app = FastAPI()

# Auth handler instance
auth_handler = AuthHandler()

# User model for registration and login
class User(BaseModel):
    username: str
    password: str

# In-memory store for users
users = []

@app.post('/register')
def register(auth_details: User):
    # Check if the user already exists
    if any(user['username'] == auth_details.username for user in users):
        raise HTTPException(status_code=400, detail='Username already exists')
    
    # Hash the password and store the user
    hashed_password = auth_handler.get_password_hash(auth_details.password)
    users.append({
        'username': auth_details.username,
        'password': hashed_password
    })
    return {"message": "User registered successfully"}

@app.post('/login')
def login(auth_details: User):
    # Fetch user details from the in-memory store
    user = next((user for user in users if user['username'] == auth_details.username), None)
    
    # Check if the user exists and if the password matches
    if not user or not auth_handler.verify_password(auth_details.password, user['password']):
        raise HTTPException(status_code=401, detail='Invalid username or password')
    
    # Create and return a JWT token
    token = auth_handler.encode_token(user['username'])
    return {'token': token}

@app.get('/protected')
def protected(username=Depends(auth_handler.auth_wrapper)):
    return {'message': f'Hello {username}, you are authorized!'}
