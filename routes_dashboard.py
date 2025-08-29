from fastapi import APIRouter, Depends, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from fastapi.templating import Jinja2Templates
from typing import Optional
import ipaddress

import crud, models
from database import get_db
from security import get_current_user, login_required, permission_required
from ip_allocator import allocate_subnet

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/dashboard/upload_config", response_class=HTMLResponse)
@permission_required("can_upload_config")
def upload_config_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("upload_config.html", {"request": request, "user": user})


@router.get("/dashboard/allocate_ip", response_class=HTMLResponse)
@permission_required("can_manage_allocations")
def allocate_ip_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)

    # Fetch blocks allowed for the user
    if user.is_admin:
        blocks = db.query(models.IPBlock).order_by(models.IPBlock.cidr).all()
    else:
        blocks = user.allowed_blocks

    # Fetch all VLANs and allocations for display
    vlans = db.query(models.VLAN).order_by(models.VLAN.vlan_id).all()
    allocations = db.query(models.Subnet).filter(
        models.Subnet.status == models.SubnetStatus.allocated
    ).order_by(models.Subnet.created_at.desc()).all()

    return templates.TemplateResponse(
        "allocate_ip.html",
        {
            "request": request,
            "user": user,
            "blocks": blocks,
            "vlans": vlans,
            "allocations": allocations,
        }
    )


@router.post("/allocate")
@permission_required("can_manage_allocations")
def allocate_ip_action(
    request: Request,
    block_id: int = Form(...),
    subnet_size: int = Form(...),
    vlan_id: Optional[int] = Form(None),
    description: str = Form(...),
    description_format: str = Form("uppercase"),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)

    # Apply description formatting
    if description_format == "uppercase":
        final_description = description.upper()
    elif description_format == "lowercase":
        final_description = description.lower()
    elif description_format == "hyphen":
        final_description = description.replace(" ", "-")
    elif description_format == "underscore":
        final_description = description.replace(" ", "_")
    else:
        final_description = description

    # Get or create the client based on the description
    client = crud.get_or_create_client(db, name=description)

    try:
        new_subnet = allocate_subnet(
            db,
            block_id=block_id,
            user=user,
            subnet_size=subnet_size,
            vlan_id=vlan_id,
            description=final_description,
            client_id=client.id
        )
    except HTTPException as e:
        # You can pass the error message to the template
        # For now, just re-raise
        raise e

    return RedirectResponse("/dashboard/allocate_ip", status_code=303)


@router.get("/dashboard/add_nat_ip", response_class=HTMLResponse)
@permission_required("can_manage_nat")
def add_nat_ip_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    clients = crud.list_clients(db)
    return templates.TemplateResponse("add_nat_ip.html", {
        "request": request,
        "user": user,
        "clients": clients,
        "error": None
    })


@router.post("/dashboard/add_nat_ip")
@permission_required("can_manage_nat")
def add_nat_ip_action(
    request: Request,
    ip_address: str = Form(...),
    client_id: int = Form(...),
    description: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)

    # Validate CIDR format
    try:
        ipaddress.ip_network(ip_address, strict=False)
    except ValueError:
        clients = crud.list_clients(db)
        return templates.TemplateResponse("add_nat_ip.html", {
            "request": request,
            "user": user,
            "clients": clients,
            "error": "Invalid CIDR format for NAT IP."
        }, status_code=400)

    # Check for duplicate NAT IP
    existing_nat = db.query(models.NatIp).filter(models.NatIp.ip_address == ip_address).first()
    if existing_nat:
        clients = crud.list_clients(db)
        return templates.TemplateResponse("add_nat_ip.html", {
            "request": request,
            "user": user,
            "clients": clients,
            "error": f"NAT IP {ip_address} already exists."
        }, status_code=400)

    crud.create_nat_ip(
        db,
        ip_address=ip_address,
        client_id=client_id,
        description=description
    )

    return RedirectResponse("/dashboard/nat_ips", status_code=303)


def get_next_available_ips(parent_cidr: str, db: Session, block_id: int, limit=100):
    try:
        parent_net = ipaddress.ip_network(parent_cidr)
        # Using a set for efficient lookups, but we must build it first.
        # This can be slow for very large networks.
        all_possible_ips = set(parent_net.hosts())
    except ValueError:
        return []

    # Get all allocated subnets in the block
    used_subnets = db.query(models.Subnet).filter(models.Subnet.block_id == block_id).all()
    for subnet in used_subnets:
        try:
            all_possible_ips.difference_update(ipaddress.ip_network(subnet.cidr))
        except ValueError:
            continue

    # Get all single IP assignments that fall within the parent block
    all_interface_addresses = db.query(models.InterfaceAddress).all()
    for addr in all_interface_addresses:
        try:
            ip = ipaddress.ip_address(addr.ip)
            if ip in parent_net:
                all_possible_ips.discard(ip)
        except ValueError:
            continue

    return sorted(list(all_possible_ips), key=ipaddress.get_mixed_type_key)[:limit]


@router.get("/api/blocks/{block_id}/available_ips")
@permission_required("can_manage_allocations")
def get_available_ips_for_block(request: Request, block_id: int, db: Session = Depends(get_db)):
    block = db.query(models.IPBlock).filter(models.IPBlock.id == block_id).first()
    if not block:
        raise HTTPException(status_code=404, detail="Block not found")

    available_ips = get_next_available_ips(block.cidr, db, block_id)

    return {"available_ips": available_ips}


@router.post("/allocate/manual")
@permission_required("can_manage_allocations")
def manual_allocate_action(
    request: Request,
    cidr: str = Form(...),
    vlan_id: Optional[int] = Form(None),
    description: str = Form(...),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)

    # Validate CIDR
    try:
        new_net = ipaddress.ip_network(cidr)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid CIDR format.")

    # Find parent block
    if user.is_admin:
        allowed_blocks = db.query(models.IPBlock).all()
    else:
        allowed_blocks = user.allowed_blocks

    parent_block = None
    for block in allowed_blocks:
        if block.cidr == 'Unassigned':
            continue
        if new_net.subnet_of(ipaddress.ip_network(block.cidr)):
            parent_block = block
            break

    if not parent_block:
        raise HTTPException(status_code=403, detail="This subnet does not belong to any of your allowed blocks.")

    # Check for overlaps
    existing_subnets = db.query(models.Subnet).filter(models.Subnet.block_id == parent_block.id).all()
    for existing in existing_subnets:
        if new_net.overlaps(ipaddress.ip_network(existing.cidr)):
            raise HTTPException(status_code=400, detail=f"Subnet overlaps with existing subnet: {existing.cidr}")

    # Get or create client
    client = crud.get_or_create_client(db, name=description)

    # Create the new subnet
    new_subnet = models.Subnet(
        cidr=str(new_net),
        status=models.SubnetStatus.allocated,
        vlan_id=vlan_id,
        description=description,
        created_by=user.username,
        block_id=parent_block.id,
        client_id=client.id
    )
    db.add(new_subnet)
    db.commit()

    return RedirectResponse("/dashboard/allocate_ip", status_code=303)
