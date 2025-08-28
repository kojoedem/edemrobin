from fastapi import APIRouter, Depends, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from fastapi.templating import Jinja2Templates
from typing import Optional

import crud, models
from database import get_db
from security import get_current_user, login_required, level_required
from ip_allocator import allocate_subnet

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/dashboard/upload_config", response_class=HTMLResponse)
@login_required
def upload_config_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("upload_config.html", {"request": request, "user": user})


@router.get("/dashboard/allocate_ip", response_class=HTMLResponse)
@login_required
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
@level_required(2)
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
@level_required(2)
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
@level_required(2)
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
