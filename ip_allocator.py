import ipaddress
from sqlalchemy.orm import Session
from fastapi import HTTPException
from typing import Optional

import crud
from models import IPBlock, Subnet, User, SubnetStatus

def allocate_subnet(
    db: Session,
    block_id: int,
    user: User,
    subnet_size: int,
    vlan_id: Optional[int] = None,
    client_id: Optional[int] = None,
    description: str="",
):
    """
    Finds the next available subnet of a given size within a parent block.
    """
    block = db.query(IPBlock).filter(IPBlock.id == block_id).first()
    if not block:
        raise HTTPException(status_code=404, detail="IP block not found")

    # The parent network from which we are allocating
    parent_network = ipaddress.ip_network(block.cidr)

    # Get all subnets that are already allocated or imported for this block
    existing_subnets_q = db.query(Subnet).filter(Subnet.block_id == block_id).all()
    existing_subnets = [ipaddress.ip_network(s.cidr) for s in existing_subnets_q]

    # Iterate through all possible subnets of the requested size
    for candidate_subnet in parent_network.subnets(new_prefix=subnet_size):

        # Check if the candidate subnet overlaps with any of the existing subnets.
        is_overlapping = False
        for existing in existing_subnets:
            if candidate_subnet.overlaps(existing):
                is_overlapping = True
                break

        # If it doesn't overlap, we've found our available subnet
        if not is_overlapping:
            return crud.create_or_get_subnet(
                db,
                cidr=str(candidate_subnet),
                block=block,
                status=SubnetStatus.allocated,
                vlan_id=vlan_id,
                client_id=client_id,
                description=description,
                created_by=user.username,
            )

    # If the loop completes, no available subnet was found
    raise HTTPException(status_code=400, detail="No available subnets of this size in the block")
