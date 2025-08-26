from pydantic import BaseModel
from datetime import datetime

class IPBase(BaseModel):
    subnet: str
    vlan: str | None = None
    description: str | None = None
    person: str
    created_at: datetime

class IPCreate(IPBase):
    pass

class IP(IPBase):
    id: int
    class Config:
        orm_mode = True

class UserBase(BaseModel):
    username: str
    level: int
    is_admin: bool

class UserCreate(BaseModel):
    username: str
    password: str
    level: int = 1
    is_admin: bool = False

class User(UserBase):
    id: int
    class Config:
        orm_mode = True
