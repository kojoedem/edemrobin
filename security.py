from passlib.context import CryptContext
from fastapi import Request, HTTPException, Depends
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

def get_current_user(request: Request, db: Session = Depends(get_db)):
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
        request: Request = kwargs["request"]
        db: Session = kwargs["db"]
        get_current_user(request, db)
        if inspect.iscoroutinefunction(endpoint):
            return await endpoint(*args, **kwargs)
        else:
            return endpoint(*args, **kwargs)
    return wrapper

def permission_required(permission_name: str):
    def decorator(endpoint):
        @wraps(endpoint)
        async def wrapper(*args, **kwargs):
            request: Request = kwargs["request"]
            db: Session = kwargs["db"]
            user = get_current_user(request, db)

            # Admins have all permissions
            if user.is_admin:
                if inspect.iscoroutinefunction(endpoint):
                    return await endpoint(*args, **kwargs)
                else:
                    return endpoint(*args, **kwargs)

            if not getattr(user, permission_name, False):
                raise HTTPException(status_code=403, detail="You do not have permission to perform this action.")

            if inspect.iscoroutinefunction(endpoint):
                return await endpoint(*args, **kwargs)
            else:
                return endpoint(*args, **kwargs)
        return wrapper
    return decorator

def admin_required(endpoint):
    @wraps(endpoint)
    async def wrapper(*args, **kwargs):
        request: Request = kwargs["request"]
        db: Session = kwargs["db"]
        user = get_current_user(request, db)
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin access required")
        if inspect.iscoroutinefunction(endpoint):
            return await endpoint(*args, **kwargs)
        else:
            return endpoint(*args, **kwargs)
    return wrapper
