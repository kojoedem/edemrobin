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
    description: str = "",
    client_id: Optional[int] = None,
):
    """
    Finds the next available subnet of a given size within a parent block.
    """
    block = db.query(IPBlock).filter(IPBlock.id == block_id).first()
    if not block:
        raise HTTPException(status_code=404, detail="IP block not found")

    # The parent network from which we are allocating
    parent_network = ipaddress.ip_network(block.cidr)

    # 1. Get all "hard-allocated" subnets (allocated or reserved)
    hard_allocated_subnets = db.query(Subnet).filter(
        Subnet.block_id == block_id,
        Subnet.status.in_([SubnetStatus.allocated, SubnetStatus.reserved])
    ).all()

    # 2. Get all individual interface IPs from "imported" subnets
    imported_subnets = db.query(Subnet).filter(
        Subnet.block_id == block_id,
        Subnet.status == SubnetStatus.imported
    ).all()

    unavailable_networks = [ipaddress.ip_network(s.cidr) for s in hard_allocated_subnets]

    from models import InterfaceAddress
    for sub in imported_subnets:
        # Get all interface IPs for this specific subnet
        interface_ips = db.query(InterfaceAddress).filter(InterfaceAddress.subnet_id == sub.id).all()
        for ip in interface_ips:
            # Treat each used IP as a /32 network for exclusion
            unavailable_networks.append(ipaddress.ip_network(f"{ip.ip}/32"))

    # 3. Collapse all unavailable networks to get a minimal set
    if not unavailable_networks:
        collapsed_existing = []
    else:
        collapsed_existing = list(ipaddress.collapse_addresses(unavailable_networks))

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
                client_id=client_id,
            )
            db.add(new_allocation)
            db.commit()
            db.refresh(new_allocation)
            return new_allocation

    # If the loop completes, no available subnet was found
    raise HTTPException(status_code=400, detail="No available subnets of this size in the block")
