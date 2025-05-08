from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
import re
import logging
from db.database import get_db
from db.models import User
from db.schemas import UserCreate
from passlib.context import CryptContext

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(tags=["Authentication"])

class AuthConfig:
    BCRYPT_ROUNDS = 12
    MIN_PASSWORD_LENGTH = 8
    MAX_USERNAME_LENGTH = 50
    PASSWORD_PATTERN = re.compile(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    )

def validate_user_input(user_data: UserCreate) -> None:
    """Validate user input data."""
    if len(user_data.HoTen) > AuthConfig.MAX_USERNAME_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username must not exceed {AuthConfig.MAX_USERNAME_LENGTH} characters"
        )
    
    if not re.match(r"^[a-zA-Z0-9\s]+$", user_data.HoTen):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username can only contain letters, numbers, and spaces"
        )

    if not AuthConfig.PASSWORD_PATTERN.match(user_data.Password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 8 characters long"
        )
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

@router.post("/register")
async def register_user(user_data: UserCreate, db: Session = Depends(get_db), request: Request=None):
    if not user_data:
        raise HTTPException()
    if validate_user_input(user_data):
        raise HTTPException()
    db_user=db.query(User).filter(User.email==user_data.Email).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists") 
    hashed_password=get_password_hash(user_data.Password)
    ip_address = request.client.host
    user = User(
        email=user_data.Email,
        hashed_password=hashed_password,
        household={"ip_address": ip_address, "devices": []},
        plan=user_data.plan
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "Đăng ký thành công"}