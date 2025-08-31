# crud.py
import ipaddress
from sqlalchemy.orm import Session
from models import (
    User, VLAN, IPBlock, Subnet, SubnetStatus, Device, Interface, InterfaceAddress, Client, NatIp
)
from schemas import UserCreate
from security import hash_password

# ---------- Users ----------
def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_users(db: Session):
    return db.query(User).all()

def create_user(db: Session, user: UserCreate):
    hashed_password = hash_password(user.password)
    db_user = User(
        username=user.username,
        password_hash=hashed_password,
        is_admin=user.is_admin,
        can_view_clients=user.can_view_clients,
        can_manage_clients=user.can_manage_clients,
        can_view_nat=user.can_view_nat,
        can_manage_nat=user.can_manage_nat,
        can_upload_config=user.can_upload_config,
        can_view_churn=user.can_view_churn,
        can_manage_allocations=user.can_manage_allocations,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# ---------- Clients ----------
def create_client(db: Session, name: str, is_active: bool = True) -> Client:
    client = Client(name=name, is_active=is_active)
    db.add(client)
    db.commit()
    db.refresh(client)
    return client

def get_client(db: Session, client_id: int) -> Client | None:
    return db.query(Client).filter(Client.id == client_id).first()

def get_client_by_name(db: Session, name: str) -> Client | None:
    return db.query(Client).filter(Client.name == name).first()

def list_clients(db: Session) -> list[Client]:
    return db.query(Client).order_by(Client.name).all()

def delete_client(db: Session, client_id: int):
    client = db.query(Client).filter(Client.id == client_id).first()
    if client:
        if client.subnets:
            raise ValueError("Cannot delete a client that has subnets associated with it.")
        db.delete(client)
        db.commit()
    return client

def get_or_create_client(db: Session, name: str, is_active: bool = True) -> Client:
    client = get_client_by_name(db, name)
    if client:
        return client
    return create_client(db, name, is_active=is_active)


# ---------- NAT IPs ----------
def create_nat_ip(db: Session, ip_address: str, client_id: int, description: str | None = None) -> NatIp:
    nat_ip = NatIp(ip_address=ip_address, client_id=client_id, description=description)
    db.add(nat_ip)
    db.commit()
    db.refresh(nat_ip)
    return nat_ip

def list_nat_ips_for_client(db: Session, client_id: int) -> list[NatIp]:
    return db.query(NatIp).filter(NatIp.client_id == client_id).all()


# ---------- VLAN ----------
def create_vlan(db: Session, vlan_id: int, name: str, created_by: str, site: str | None = None):
    vlan = VLAN(vlan_id=vlan_id, name=name, created_by=created_by, site=site)
    db.add(vlan)
    db.commit()
    db.refresh(vlan)
    return vlan

def get_vlan_by_id(db: Session, vlan_id: int):
    return db.query(VLAN).filter(VLAN.vlan_id == vlan_id).first()

def list_vlans(db: Session):
    return db.query(VLAN).order_by(VLAN.vlan_id).all()

def get_or_create_vlan(db: Session, vlan_id: int, created_by: str, name: str | None = None) -> VLAN:
    """
    Gets a VLAN by its ID, or creates it if it doesn't exist.
    A default name will be used if not provided.
    Handles potential name collisions by appending the VLAN ID.
    """
    vlan = get_vlan_by_id(db, vlan_id)
    if vlan:
        return vlan

    final_name = name or f"VLAN-{vlan_id}"

    # Check if a VLAN with this name already exists
    existing_by_name = db.query(VLAN).filter(VLAN.name == final_name).first()
    if existing_by_name:
        # If the name is taken, append the VLAN ID to make it unique
        final_name = f"{final_name} ({vlan_id})"

    return create_vlan(db, vlan_id=vlan_id, name=final_name, created_by=created_by)

# ---------- Blocks & Subnets ----------
def get_or_create_block(db: Session, cidr: str, created_by: str | None = None, description: str | None = None):
    block = db.query(IPBlock).filter(IPBlock.cidr == cidr).first()
    if block:
        return block
    block = IPBlock(cidr=cidr, created_by=created_by, description=description)
    db.add(block)
    db.commit()
    db.refresh(block)
    return block

def create_or_get_subnet(db: Session, cidr: str, block: IPBlock, status: SubnetStatus, created_by: str | None = None, vlan_id: int | None = None, client_id: int | None = None, description: str | None = None):
    sub = db.query(Subnet).filter(Subnet.cidr == cidr).first()
    if sub:
        return sub
    sub = Subnet(
        cidr=cidr,
        status=status,
        block_id=block.id,
        vlan_id=vlan_id,
        client_id=client_id,
        description=description,
        created_by=created_by,
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)
    return sub

def list_blocks_with_utilization(db: Session):
    blocks = db.query(IPBlock).all()
    results = []
    for b in blocks:
        used = len(b.subnets)
        results.append({
            "block": b,
            "subnets": used,
        })
    return results

# ---------- Devices & Interfaces ----------
def get_or_create_device(db: Session, hostname: str, vendor: str = "cisco", model: str | None = None, mgmt_ip: str | None = None, site: str | None = None, username: str | None = None, password: str | None = None):
    dev = db.query(Device).filter(Device.hostname == hostname).first()
    if dev:
        # Update existing device's credentials if provided
        if username:
            dev.username = username
        if password:
            dev.password = password
        db.commit()
        db.refresh(dev)
        return dev

    dev = Device(
        hostname=hostname,
        vendor=vendor,
        model=model,
        mgmt_ip=mgmt_ip,
        site=site,
        username=username,
        password=password
    )
    db.add(dev)
    db.commit()
    db.refresh(dev)
    return dev

def get_or_create_interface(db: Session, device: Device, name: str, description: str | None = None, vlan_id: int | None = None):
    itf = db.query(Interface).filter(Interface.device_id == device.id, Interface.name == name).first()
    if itf:
        return itf
    itf = Interface(device_id=device.id, name=name, description=description, vlan_id=vlan_id)
    db.add(itf)
    db.commit()
    db.refresh(itf)
    return itf

def add_interface_address(db: Session, interface: Interface, ip: str, prefix: int, subnet_id: int | None = None, gateway: str | None = None):
    addr = InterfaceAddress(interface_id=interface.id, ip=ip, prefix=prefix, subnet_id=subnet_id, gateway=gateway)
    db.add(addr)
    db.commit()
    db.refresh(addr)
    return addr

# ---------- Helpers for grouping ----------
def suggest_block_for_network(network: ipaddress.IPv4Network) -> str:
    """
    Decide which BLOCK to place this network under.
    Simple heuristic:
    - If prefix <= /16, keep as-is (e.g., 10.0.0.0/8 or 172.16.0.0/16)
    - Else, promote to /16 supernet
    """
    if network.prefixlen <= 16:
        return str(network)
    return str(network.supernet(new_prefix=16))
