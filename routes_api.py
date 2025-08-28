from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
import ipaddress

from database import get_db
from models import IPBlock, Subnet, SubnetStatus, InterfaceAddress
from security import permission_required

router = APIRouter(prefix="/api", tags=["API"])

@router.get("/blocks/{block_id}/available_subnets/{subnet_size}", response_model=List[str], dependencies=[Depends(permission_required("can_manage_allocations"))])
def get_available_subnets(block_id: int, subnet_size: int, db: Session = Depends(get_db)):
    """
    Calculates and returns a list of available subnets of a given size within a parent block.
    """
    block = db.query(IPBlock).filter(IPBlock.id == block_id).first()
    if not block:
        raise HTTPException(status_code=404, detail="IP block not found")

    try:
        parent_network = ipaddress.ip_network(block.cidr)
    except ValueError:
        return [] # Invalid block CIDR, return no subnets

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

    for sub in imported_subnets:
        interface_ips = db.query(InterfaceAddress).filter(InterfaceAddress.subnet_id == sub.id).all()
        for ip in interface_ips:
            unavailable_networks.append(ipaddress.ip_network(f"{ip.ip}/32"))

    # 3. Collapse all unavailable networks
    if not unavailable_networks:
        collapsed_existing = []
    else:
        collapsed_existing = list(ipaddress.collapse_addresses(unavailable_networks))

    # 4. Calculate available ranges by excluding the existing networks
    available_ranges = [parent_network]
    for existing in collapsed_existing:
        new_available = []
        for avail in available_ranges:
            if avail.overlaps(existing):
                new_available.extend(list(avail.address_exclude(existing)))
            else:
                new_available.append(avail)
        available_ranges = new_available

    available_ranges.sort()

    # 5. Find all available subnets in the calculated ranges
    all_available_subnets = []
    for avail_range in available_ranges:
        if avail_range.prefixlen > subnet_size:
            continue

        for candidate_subnet in avail_range.subnets(new_prefix=subnet_size):
            all_available_subnets.append(str(candidate_subnet))
            if len(all_available_subnets) >= 200: # Add a limit to prevent performance issues
                break
        if len(all_available_subnets) >= 200:
            break

    return all_available_subnets
