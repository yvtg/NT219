from fastapi import APIRouter, Depends, HTTPException, Request, status, FastAPI
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from pydantic import EmailStr, BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta
import re
import logging
from typing import Optional, List
from sqlalchemy import create_engine, Column, Integer, String, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Khởi tạo FastAPI và Router
app = FastAPI()
router = APIRouter(tags=["Authentication"])

# Cấu hình PostgreSQL
DATABASE_URL = "postgresql://neondb_owner:npg_M1ikE6zudbVt@ep-odd-fire-a4dt9cd1-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Cấu hình JWT
SECRET_KEY = "your_jwt_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Cấu hình mã hóa mật khẩu
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Mô hình User trong PostgreSQL
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    ho_ten = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")  # user hoặc admin
    household = Column(JSON, default={"ip_address": "", "devices": []})
    plan = Column(String, default="basic")  # basic, standard, premium

# Tạo bảng
Base.metadata.create_all(bind=engine)

# Pydantic schemas
class UserCreate(BaseModel):
    Email: EmailStr
    HoTen: str
    Password: str
    plan: str

class UserResponse(BaseModel):
    email: EmailStr
    ho_ten: str
    plan: str

# Hàm phụ trợ
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Không thể xác thực token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

# Cấu hình xác thực
class AuthConfig:
    BCRYPT_ROUNDS = 12
    MIN_PASSWORD_LENGTH = 8
    MAX_USERNAME_LENGTH = 50
    # Mở rộng tập ký tự đặc biệt
    PASSWORD_PATTERN = re.compile(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:'\",.<>?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};:'\",.<>?]{8,}$"
    )

def validate_user_input(user_data: UserCreate) -> None:
    """Validate user input data."""
    logger.info(f"Validating user input: Email={user_data.Email}, HoTen={user_data.HoTen}")
    
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

    # Kiểm tra và ghi log chi tiết về mật khẩu
    password = user_data.Password.strip()
    if not password:
        logger.error("Password is empty or contains only whitespace")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password cannot be empty"
        )
    
    if not AuthConfig.PASSWORD_PATTERN.match(password):
        logger.error(f"Password validation failed: {password}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one uppercase letter, one lowercase letter, one number, one special character (!@#$%^&*()_+-=[]{};:'\",.<>?), and be at least 8 characters long"
        )

# API Đăng ký
@router.post("/register", response_model=UserResponse)
async def register_user(user_data: UserCreate, db: Session = Depends(get_db), request: Request = None):
    # Kiểm tra dữ liệu đầu vào
    if not user_data:
        logger.error("Invalid input data: Empty user_data")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Dữ liệu không hợp lệ"
        )
    
    # Xác thực đầu vào
    validate_user_input(user_data)

    # Kiểm tra email tồn tại
    db_user = db.query(User).filter(User.email == user_data.Email).first()
    if db_user:
        logger.warning(f"Registration attempt with existing email: {user_data.Email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email đã được sử dụng"
        )

    # Mã hóa mật khẩu
    hashed_password = get_password_hash(user_data.Password)

    # Lấy IP của thiết bị
    ip_address = request.client.host

    # Tạo user mới
    user = User(
        email=user_data.Email,
        ho_ten=user_data.HoTen,
        hashed_password=hashed_password,
        household={"ip_address": ip_address, "devices": []},
        plan=user_data.plan
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info(f"User registered: {user.email}")
    
    return UserResponse(email=user.email, ho_ten=user.ho_ten, plan=user.plan)

# API Đăng nhập
@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db), request: Request = None):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning(f"Failed login attempt for email: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email hoặc mật khẩu không đúng",
            headers={"WWW-Authenticate": "Bearer"},
        )

    ip_address = request.client.host
    device_id = form_data.client_id or "unknown_device"
    
    if user.household["ip_address"] and user.household["ip_address"] != ip_address:
        logger.info(f"IP mismatch for user {user.email}: {ip_address}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Thiết bị không thuộc Hộ gia đình Netflix. Vui lòng xác minh.",
            headers={"X-Requires-Verification": "true"}
        )

    max_devices = 4 if user.plan == "premium" else 2 if user.plan == "standard" else 1
    devices = user.household.get("devices", [])
    device_exists = any(d["device_id"] == device_id for d in devices)

    if not device_exists and len(devices) >= max_devices:
        logger.warning(f"Device limit exceeded for user {user.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Đã vượt quá giới hạn thiết bị"
        )

    if not device_exists:
        devices.append({"device_id": device_id, "last_used": datetime.utcnow().isoformat()})
        user.household["devices"] = devices
        db.commit()

    access_token = create_access_token(data={"sub": str(user.id), "role": user.role})
    logger.info(f"User logged in: {user.email}")
    return {"access_token": access_token, "token_type": "bearer"}

# API Nội dung (bảo vệ)
@router.get("/content")
async def get_content(current_user: User = Depends(get_current_user)):
    if current_user.role in ["user", "admin"]:
        return {"message": "Truy cập nội dung thành công", "content": "Danh sách phim..."}
    logger.warning(f"Unauthorized content access by user: {current_user.email}")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Không có quyền truy cập"
    )

# API Admin (chỉ admin)
@router.get("/admin")
async def admin_panel(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        logger.warning(f"Unauthorized admin access by user: {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Chỉ admin mới có quyền truy cập"
        )
    return {"message": "Truy cập admin thành công"}

# API Xác minh hộ gia đình
@router.post("/verify-household")
async def verify_household(
    verification_code: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    expected_code = "123456"  # Giả lập mã xác minh
    if verification_code != expected_code:
        logger.error(f"Invalid verification code for user: {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mã xác minh không đúng"
        )

    current_user.household["ip_address"] = request.client.host
    db.commit()
    logger.info(f"Household verified for user: {current_user.email}")
    return {"message": "Xác minh hộ gia đình thành công"}

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # hoặc "*" nếu bạn đang test
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Gắn router vào app
app.include_router(router)

# Khởi động server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)