import ipaddress
from sqlalchemy.orm import Session
from fastapi import HTTPException
from models import IPBlock, IPAddress, User

def allocate_subnet(
    db: Session,
    block_id: int,
    user: User,
    subnet_size: int = 29,
):
    block = db.query(IPBlock).filter(IPBlock.id == block_id).first()
    if not block:
        raise HTTPException(status_code=404, detail="IP block not found")

    network = ipaddress.ip_network(block.cidr)
    used_subnets = [
        ipaddress.ip_network(ip.subnet)
        for ip in db.query(IPAddress).filter(IPAddress.block_id == block_id).all()
    ]

    for candidate in network.subnets(new_prefix=subnet_size):
        if candidate not in used_subnets:
            allocation = IPAddress(
                subnet=str(candidate),
                vlan=None,
                description=None,
                created_by=user.username,
                block_id=block_id,
                creator_id=user.id,
            )
            db.add(allocation)
            db.commit()
            db.refresh(allocation)
            return allocation

    raise HTTPException(status_code=400, detail="No available subnets in this block")
