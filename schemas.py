# schemas.py
from pydantic import BaseModel, ConfigDict
from typing import Optional, Literal
from datetime import datetime

class VLANBase(BaseModel):
    vlan_id: int
    name: str
    site: Optional[str] = None

class VLAN(VLANBase):
    id: int
    created_by: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class IPBlockBase(BaseModel):
    cidr: str
    description: Optional[str] = None

class IPBlock(IPBlockBase):
    id: int
    created_by: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    is_admin: bool = False
    can_view_clients: bool = False
    can_manage_clients: bool = False
    can_view_nat: bool = False
    can_manage_nat: bool = False
    can_upload_config: bool = False
    can_view_churn: bool = False
    can_manage_allocations: bool = False
    can_manage_core_devices: bool = False

class User(UserBase):
    id: int
    is_admin: bool
    can_view_clients: bool
    can_manage_clients: bool
    can_view_nat: bool
    can_manage_nat: bool
    can_upload_config: bool
    can_view_churn: bool
    can_manage_allocations: bool
    can_manage_core_devices: bool
    model_config = ConfigDict(from_attributes=True)

class Subnet(BaseModel):
    id: int
    cidr: str
    status: Literal["imported","allocated","reserved"]
    vlan_id: Optional[int] = None
    description: Optional[str] = None
    block_id: int
    created_by: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
