from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    level = Column(Integer, default=1)  # 1=view, 2=allocate, 3=admin (example)
    is_admin = Column(Boolean, default=False)

class IPEntry(Base):
    __tablename__ = "ips"
    id = Column(Integer, primary_key=True, index=True)
    subnet = Column(String, unique=True, index=True, nullable=False)
    vlan = Column(String, nullable=True)
    description = Column(String, nullable=True)
    person = Column(String, nullable=False)  # stored as username for simplicity
    created_at = Column(DateTime, nullable=False)
