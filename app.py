from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo.mongo_client import MongoClient
from pydantic import BaseModel, EmailStr, Field
import bcrypt
import uuid
import os
from dotenv import load_dotenv
import re
from datetime import datetime, timedelta
from jose import jwt, JWTError
import logging
from typing import Optional

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# MongoDB connection
uri = os.getenv("MONGODB_URI")
if not uri:
    logger.error("MONGODB_URI environment variable not set")
    raise RuntimeError("MONGODB_URI environment variable not set")

client = MongoClient(uri)
db = client["DataManagement"]
users_collection = db["users"]

# FastAPI app
app = FastAPI()

# Enable CORS: use ALLOWED_ORIGINS env variable if set, otherwise allow all origins.
allowed_origins = os.getenv("ALLOWED_ORIGINS", "")
if allowed_origins:
    allowed_origins = allowed_origins.split(",")
else:
    allowed_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,  # For production, specify exact domains.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    logger.error("SECRET_KEY environment variable not set")
    raise RuntimeError("SECRET_KEY environment variable not set")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 1))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))
REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS", 30))

# Security dependency using HTTPBearer
security = HTTPBearer()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(days=7))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
    except JWTError as e:
        logger.error(f"JWT error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    user = users_collection.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user

def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def normalize_email(email: str) -> str:
    return email.strip().lower()

def get_user_by_email(email: str):
    return users_collection.find_one({"email": normalize_email(email)})

# Pydantic Models
class UserSignUp(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    # Removed additional password validation

class UserSignIn(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    # New field for "remember me" functionality.
    remember_me: Optional[bool] = False

class UpdatePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=8)
    new_password: str = Field(..., min_length=8)
    # Removed additional password validation

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# Updated SignInResponse model to include token expiration times
class SignInResponse(TokenResponse):
    refresh_token: str
    access_token_expires_at: datetime
    refresh_token_expires_at: datetime

class TokenRefreshRequest(BaseModel):
    refresh_token: str

class UserProfile(BaseModel):
    user_id: str
    username: str
    email: EmailStr

# Protected endpoint: Get user profile
@app.get("/profile", response_model=UserProfile)
async def get_profile(current_user: dict = Depends(get_current_user)):
    return UserProfile(
        user_id=current_user["user_id"],
        username=current_user["username"],
        email=current_user["email"],
    )

# Signup Endpoint
@app.post("/signup", status_code=status.HTTP_201_CREATED)
async def sign_up(user: UserSignUp):
    email = normalize_email(user.email)
    if get_user_by_email(email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already exists",
        )
    hashed_password = hash_password(user.password)
    user_id = str(uuid.uuid4())
    user_data = {
        "user_id": user_id,
        "username": user.username,
        "email": email,
        "password": hashed_password,
        "created_at": datetime.utcnow(),
    }
    try:
        users_collection.insert_one(user_data)
    except Exception as e:
        logger.error(f"Database insertion error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error",
        )
    return {"message": "User registered successfully"}

# Signin Endpoint (returns both access and refresh tokens along with expiration times)
@app.post("/signin", response_model=SignInResponse)
async def sign_in(user: UserSignIn):
    email = normalize_email(user.email)
    user_record = get_user_by_email(email)
    if not user_record or not verify_password(user.password, user_record["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    if user.remember_me:
        refresh_token_expires = timedelta(days=REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS)
    else:
        refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    # Calculate expiration datetimes
    access_token_expires_at = datetime.utcnow() + access_token_expires
    refresh_token_expires_at = datetime.utcnow() + refresh_token_expires

    access_token = create_access_token(
        data={"sub": user_record["user_id"]},
        expires_delta=access_token_expires,
    )
    refresh_token = create_refresh_token(
        data={"sub": user_record["user_id"]},
        expires_delta=refresh_token_expires,
    )
    return SignInResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        access_token_expires_at=access_token_expires_at,
        refresh_token_expires_at=refresh_token_expires_at,
    )

# Refresh Token Endpoint
@app.post("/refresh-token", response_model=TokenResponse)
async def refresh_access_token(request: TokenRefreshRequest):
    token = request.refresh_token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
    except JWTError as e:
        logger.error(f"JWT error during token refresh: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )
    user = users_collection.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_token(
        data={"sub": user_id},
        expires_delta=access_token_expires,
    )
    return TokenResponse(access_token=new_access_token, token_type="bearer")

# Update Password Endpoint (requires a valid access token)
@app.post("/update-password")
async def update_password(
    request: UpdatePasswordRequest, current_user: dict = Depends(get_current_user)
):
    if not verify_password(request.old_password, current_user["password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Old password is incorrect",
        )
    if verify_password(request.new_password, current_user["password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password cannot be the same as the old password",
        )
    hashed_password = hash_password(request.new_password)
    try:
        users_collection.update_one(
            {"user_id": current_user["user_id"]},
            {"$set": {
                "password": hashed_password,
                "password_updated_at": datetime.utcnow()
            }},
        )
    except Exception as e:
        logger.error(f"Database update error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error",
        )
    return {"message": "Password updated successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
