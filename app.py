from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pymongo.mongo_client import MongoClient
from pydantic import BaseModel, EmailStr, Field, field_validator
import bcrypt
import uuid
import os
from dotenv import load_dotenv
import re
from datetime import datetime, timedelta
from jose import jwt, JWTError

# Load environment variables
load_dotenv()

# MongoDB connection
uri = os.getenv("MONGODB_URI")
if not uri:
    raise RuntimeError("MONGODB_URI environment variable not set")

client = MongoClient(uri)
db = client["DataManagement"]
users_collection = db["users"]

# FastAPI app
app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change "*" to frontend domain if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# Models
class UserSignUp(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", value):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[@$!%*?&#]", value):
            raise ValueError("Password must contain at least one special character")
        return value


class UserSignIn(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class UpdatePasswordRequest(BaseModel):
    email: EmailStr
    old_password: str = Field(..., min_length=8)
    new_password: str = Field(..., min_length=8)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value):
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", value):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[@$!%*?&#]", value):
            raise ValueError("Password must contain at least one special character")
        return value


# Utility functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def normalize_email(email: str) -> str:
    return email.strip().lower()


def get_user_by_email(email: str):
    return users_collection.find_one({"email": normalize_email(email)})


# Routes
@app.post("/signup")
async def sign_up(user: UserSignUp):
    email = normalize_email(user.email)
    if get_user_by_email(email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email already exists"
        )

    hashed_password = hash_password(user.password)
    user_id = str(uuid.uuid4())
    user_data = {
        "user_id": user_id,
        "username": user.username,
        "email": email,
        "password": hashed_password,
    }
    users_collection.insert_one(user_data)

    return {"message": "User registered successfully"}


@app.post("/signin")
async def sign_in(user: UserSignIn):
    email = normalize_email(user.email)
    user_record = get_user_by_email(email)
    if not user_record or not verify_password(user.password, user_record["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
        )

    return {"message": "User signed in successfully"}


# Update Password Route
@app.post("/update-password")
async def update_password(request: UpdatePasswordRequest):
    email = normalize_email(request.email)
    user_record = get_user_by_email(email)

    if not user_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Email not found"
        )

    # Check if old password matches
    if not verify_password(request.old_password, user_record["password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Old password is incorrect"
        )

    # Prevent setting the same password
    if verify_password(request.new_password, user_record["password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password cannot be the same as the old password",
        )

    hashed_password = hash_password(request.new_password)

    # Update password and timestamp
    users_collection.update_one(
        {"email": email},
        {
            "$set": {
                "password": hashed_password,
                "password_updated_at": datetime.utcnow(),
            }
        },
    )

    return {"message": "Password updated successfully", "email": email}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
