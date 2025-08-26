from functools import wraps
from fastapi import Request, HTTPException
from sqlalchemy.orm import Session
from passlib.hash import bcrypt
import crud, models
from database import SessionLocal

def hash_password(password: str) -> str:
    return bcrypt.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.verify(password, password_hash)

def get_current_user(request: Request, db: Session | None = None) -> models.User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
    try:
        user = crud.get_user_by_id(db, user_id)
        return user
    finally:
        if close_db:
            db.close()

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Find Request among args/kwargs
        request = None
        for a in args:
            if isinstance(a, Request):
                request = a
                break
        if request is None and "request" in kwargs:
            request = kwargs["request"]
        if request is None:
            raise HTTPException(status_code=500, detail="Request object not found")
        user = get_current_user(request)
        if not user:
            raise HTTPException(status_code=303, detail="Redirect", headers={"Location": "/login"})
        return func(*args, **kwargs)
    return wrapper

def level_required(min_level: int):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            request = None
            for a in args:
                if isinstance(a, Request):
                    request = a
                    break
            if request is None and "request" in kwargs:
                request = kwargs["request"]
            if request is None:
                raise HTTPException(status_code=500, detail="Request object not found")
            user = get_current_user(request)
            if not user:
                raise HTTPException(status_code=303, detail="Redirect", headers={"Location": "/login"})
            if user.level < min_level:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return func(*args, **kwargs)
        return wrapper
    return decorator

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        request = None
        for a in args:
            if isinstance(a, Request):
                request = a
                break
        if request is None and "request" in kwargs:
            request = kwargs["request"]
        if request is None:
            raise HTTPException(status_code=500, detail="Request object not found")
        user = get_current_user(request)
        if not user:
            raise HTTPException(status_code=303, detail="Redirect", headers={"Location": "/login"})
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only")
        return func(*args, **kwargs)
    return wrapper
