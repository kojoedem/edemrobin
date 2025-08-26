from sqlalchemy.orm import Session
from typing import Optional, List
import models, schemas
from security import hash_password

# ---- Users ----
def count_users(db: Session) -> int:
    return db.query(models.User).count()

def create_user(db: Session, username: str, password: str, level: int = 1, is_admin: bool = False) -> models.User:
    user = models.User(
        username=username,
        password_hash=hash_password(password),
        level=level,
        is_admin=is_admin,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def get_user_by_id(db: Session, user_id: int) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_username(db: Session, username: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.username == username).first()

def get_users(db: Session) -> List[models.User]:
    return db.query(models.User).order_by(models.User.username.asc()).all()

# ---- IPs ----
def create_ip(db: Session, ip: schemas.IPCreate):
    db_ip = models.IPEntry(**ip.dict())
    db.add(db_ip)
    db.commit()
    db.refresh(db_ip)
    return db_ip

def get_ips(db: Session):
    return db.query(models.IPEntry).order_by(models.IPEntry.created_at.desc()).all()

def get_all_subnets(db: Session):
    return [row.subnet for row in db.query(models.IPEntry).all()]
