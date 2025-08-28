import ipaddress
from sqlalchemy.orm import Session
from fastapi import HTTPException
from typing import Optional

from models import IPBlock, Subnet, User, SubnetStatus

def allocate_subnet(
    db: Session,
    block_id: int,
    user: User,
    subnet_size: int,
    vlan_id: Optional[int] = None,
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
    existing_networks = [ipaddress.ip_network(s.cidr) for s in existing_subnets_q]

    # Collapse the existing networks to handle overlaps and adjacencies
    collapsed_existing = list(ipaddress.collapse_addresses(existing_networks))

    # Calculate the available ranges by excluding the existing networks from the parent
    available_ranges = [parent_network]
    for existing in collapsed_existing:
        new_available = []
        for avail in available_ranges:
            if avail.overlaps(existing):
                new_available.extend(list(avail.address_exclude(existing)))
            else:
                new_available.append(avail)
        available_ranges = new_available

    # Sort the ranges to ensure we start from the lowest available address
    available_ranges.sort()

    # Find the first available subnet in the calculated ranges
    for avail_range in available_ranges:
        if avail_range.prefixlen > subnet_size:
            continue  # This range is smaller than the requested subnet size

        # Iterate through possible subnets in the available range
        for candidate_subnet in avail_range.subnets(new_prefix=subnet_size):
            # Since we are iterating within an available range, the first one we find is guaranteed to be free
            new_allocation = Subnet(
                cidr=str(candidate_subnet),
                status=SubnetStatus.allocated,
                vlan_id=vlan_id,
                description=description,
                created_by=user.username,
                block_id=block.id,
            )
            db.add(new_allocation)
            db.commit()
            db.refresh(new_allocation)
            return new_allocation

    # If the loop completes, no available subnet was found
    raise HTTPException(status_code=400, detail="No available subnets of this size in the block")
