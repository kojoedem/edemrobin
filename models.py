# models.py
from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, DateTime, Enum, UniqueConstraint, Table
from sqlalchemy.orm import relationship
from datetime import datetime
from enum import Enum as PyEnum
from database import Base


# Association Table for User <-> IPBlock
user_ip_block_association = Table('user_ip_block_association', Base.metadata,
    Column('user_id', ForeignKey('users.id'), primary_key=True),
    Column('ip_block_id', ForeignKey('ip_blocks.id'), primary_key=True)
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_admin = Column(Boolean, default=False, nullable=False, server_default="false")

    # Granular Permissions
    can_view_clients = Column(Boolean, default=False, nullable=False, server_default="false")
    can_manage_clients = Column(Boolean, default=False, nullable=False, server_default="false")
    can_view_nat = Column(Boolean, default=False, nullable=False, server_default="false")
    can_manage_nat = Column(Boolean, default=False, nullable=False, server_default="false")
    can_upload_config = Column(Boolean, default=False, nullable=False, server_default="false")
    can_view_churn = Column(Boolean, default=False, nullable=False, server_default="false")
    can_manage_allocations = Column(Boolean, default=False, nullable=False, server_default="false")

    allowed_blocks = relationship(
        "IPBlock",
        secondary=user_ip_block_association,
        back_populates="allowed_users"
    )


class Client(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, server_default="true")
    created_at = Column(DateTime, default=datetime.utcnow)

    subnets = relationship("Subnet", back_populates="client")
    nat_ips = relationship("NatIp", back_populates="client")


class NatIp(Base):
    __tablename__ = "nat_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    client = relationship("Client", back_populates="nat_ips")


class VLAN(Base):
    __tablename__ = "vlans"

    id = Column(Integer, primary_key=True, index=True)
    vlan_id = Column(Integer, unique=True, nullable=False)
    name = Column(String, unique=True, nullable=False)
    site = Column(String, nullable=True)
    created_by = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class IPBlock(Base):
    __tablename__ = "ip_blocks"

    id = Column(Integer, primary_key=True, index=True)
    cidr = Column(String, unique=True, index=True, nullable=False)  # e.g. 192.168.0.0/16
    description = Column(String, nullable=True)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    subnets = relationship("Subnet", back_populates="block", cascade="all, delete-orphan")
    allowed_users = relationship(
        "User",
        secondary=user_ip_block_association,
        back_populates="allowed_blocks"
    )


class SubnetStatus(PyEnum):
    imported = "imported"
    allocated = "allocated"
    reserved = "reserved"
    deactivated = "deactivated"
    inactive = "inactive"
    nat = "nat"


class Subnet(Base):
    __tablename__ = "subnets"

    id = Column(Integer, primary_key=True, index=True)
    cidr = Column(String, index=True, nullable=False)
    status = Column(Enum(SubnetStatus), default=SubnetStatus.imported, nullable=False)
    vlan_id = Column(Integer, ForeignKey("vlans.id"), nullable=True)
    description = Column(String, nullable=False)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    block_id = Column(Integer, ForeignKey("ip_blocks.id"), nullable=False)
    block = relationship("IPBlock", back_populates="subnets")

    vlan = relationship("VLAN", lazy="joined")

    client_id = Column(Integer, ForeignKey("clients.id"), nullable=True)
    client = relationship("Client", back_populates="subnets")

    __table_args__ = (
        UniqueConstraint("cidr", name="uq_subnets_cidr"),
    )


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, unique=True, nullable=False)
    vendor = Column(String, default="cisco")
    model = Column(String, nullable=True)
    mgmt_ip = Column(String, nullable=True)
    site = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    interfaces = relationship("Interface", back_populates="device", cascade="all, delete-orphan")


class Interface(Base):
    __tablename__ = "interfaces"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    name = Column(String, nullable=False)  # e.g. GigabitEthernet0/0
    description = Column(String, nullable=True)
    vlan_id = Column(Integer, ForeignKey("vlans.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    device = relationship("Device", back_populates="interfaces")
    vlan = relationship("VLAN", lazy="joined")
    addresses = relationship("InterfaceAddress", back_populates="interface", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("device_id", "name", name="uq_interface_per_device"),
    )


class IPStatus(PyEnum):
    imported = "imported"
    allocated = "allocated"
    reserved = "reserved"
    free = "free"


class InterfaceAddress(Base):
    __tablename__ = "interface_addresses"

    id = Column(Integer, primary_key=True, index=True)
    interface_id = Column(Integer, ForeignKey("interfaces.id"), nullable=False)
    ip = Column(String, nullable=False)
    prefix = Column(Integer, nullable=False)
    status = Column(Enum(IPStatus), default=IPStatus.imported, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    subnet_id = Column(Integer, ForeignKey("subnets.id"), nullable=True)

    interface = relationship("Interface", back_populates="addresses")


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String, primary_key=True, index=True)
    value = Column(String, nullable=True)
