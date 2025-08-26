from passlib.context import CryptContext
from fastapi import Request, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal
from models import User
from functools import wraps

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db: Session):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session")
    return user

def login_required(endpoint):
    @wraps(endpoint)
    def wrapper(*args, **kwargs):
        request: Request = kwargs.get("request")
        db: Session = kwargs.get("db")
        get_current_user(request, db)
        return endpoint(*args, **kwargs)
    return wrapper

def level_required(min_level: int):
    def decorator(endpoint):
        @wraps(endpoint)
        def wrapper(*args, **kwargs):
            request: Request = kwargs.get("request")
            db: Session = kwargs.get("db")
            user = get_current_user(request, db)
            if user.level < min_level:
                raise HTTPException(status_code=403, detail="Insufficient permission level")
            return endpoint(*args, **kwargs)
        return wrapper
    return decorator

def admin_required(endpoint):
    @wraps(endpoint)
    def wrapper(*args, **kwargs):
        request: Request = kwargs.get("request")
        db: Session = kwargs.get("db")
        user = get_current_user(request, db)
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin access required")
        return endpoint(*args, **kwargs)
    return wrapper
