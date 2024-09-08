import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

class AuthHandler:
    # Security dependency for extracting bearer token
    security = HTTPBearer()
    
    # Password hashing context using bcrypt
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    # Secret key for JWT (loaded from .env)
    secret = os.getenv('SECRET_KEY', 'my_jwt_secret')

    # Hash the plain password
    def get_password_hash(self, password):
        return self.pwd_context.hash(password)

    # Verify the plain password against the hashed password
    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)

    # Encode a JWT token with a username
    def encode_token(self, username):
        payload = {
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow(),
            'sub': username
        }
        return jwt.encode(payload, self.secret, algorithm='HS256')

    # Decode and verify the JWT token
    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Token has expired')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid token')

    # Extract and decode the token from Authorization header
    def auth_wrapper(self, auth: HTTPAuthorizationCredentials = Security(security)):
        return self.decode_token(auth.credentials)
