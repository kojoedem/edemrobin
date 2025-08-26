from passlib.context import CryptContext
from fastapi import Request, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal
from models import User
from functools import wraps
import inspect

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

from models import Setting

def get_current_user(request: Request, db: Session):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session")

    # Also load settings and attach to request state for use in templates
    settings_db = db.query(Setting).all()
    request.state.settings = {s.key: s.value for s in settings_db}

    return user

def login_required(endpoint):
    @wraps(endpoint)
    async def wrapper(*args, **kwargs):
        request: Request = kwargs.get("request")
        db: Session = kwargs.get("db")
        # This will raise an exception if not logged in, handled by FastAPI
        get_current_user(request, db)
        # Await the actual endpoint function
        return await endpoint(*args, **kwargs)
    return wrapper

def level_required(min_level: int):
    def decorator(endpoint):
        @wraps(endpoint)
        async def wrapper(*args, **kwargs):
            request: Request = kwargs.get("request")
            db: Session = kwargs.get("db")
            user = get_current_user(request, db)
            if user.level < min_level:
                raise HTTPException(status_code=403, detail="Insufficient permission level")
            # Await the actual endpoint function
            return await endpoint(*args, **kwargs)
        return wrapper
    return decorator

def admin_required(endpoint):
    @wraps(endpoint)
    async def wrapper(*args, **kwargs):
        request: Request = kwargs.get("request")
        db: Session = kwargs.get("db")
        user = get_current_user(request, db)
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin access required")
        # Await the actual endpoint function
        return await endpoint(*args, **kwargs)
    return wrapper
