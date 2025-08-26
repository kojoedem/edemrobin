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
