from fastapi import FastAPI, Depends, HTTPException, Request, Form, File, UploadFile
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, List
import os, re, ipaddress, io, csv, shutil
from starlette.responses import StreamingResponse
from PIL import Image, ImageDraw, ImageFont

import crud, models, schemas
from database import engine, Base, SessionLocal
from ip_allocator import allocate_subnet
from security import hash_password, verify_password, get_current_user, login_required, admin_required, level_required

from routes_import import router as import_router
from routes_allocate import router as allocate_router
from routes_dashboard import router as dashboard_router
from routes_vlan import router as vlan_router
from utils import parse_config


Base.metadata.create_all(bind=engine)

app = FastAPI(title="IP DB")
app.add_middleware(SessionMiddleware, secret_key="supersecretkey")

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(import_router)
app.include_router(allocate_router)
app.include_router(vlan_router)
app.include_router(dashboard_router)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.on_event("startup")
def bootstrap_admin():
    db = SessionLocal()
    try:
        admin = crud.get_user_by_username(db, "admin")
        if not admin:
            crud.create_user(db, "admin", "admin123", level=3, is_admin=True)
            print("\n⚠️ Default admin created: username=admin, password=admin123. Change immediately!\n")
    finally:
        db.close()


templates = Jinja2Templates(directory="templates")

from sqlalchemy import or_

@app.get("/")
def home(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    # --- Stats ---
    vlan_count = db.query(models.VLAN).count()
    client_count = db.query(models.Client).filter(models.Client.is_active == True).count()

    if user.is_admin:
        blocks_for_stats = db.query(models.IPBlock).filter(models.IPBlock.cidr != "Unassigned").order_by(models.IPBlock.cidr).all()
    else:
        blocks_for_stats = [b for b in user.allowed_blocks if b.cidr != "Unassigned"]
        blocks_for_stats.sort(key=lambda x: ipaddress.ip_network(x.cidr))

    block_stats = []
    for block in blocks_for_stats:
        try:
            parent_network = ipaddress.ip_network(block.cidr)
            total_ips = parent_network.num_addresses
            active_subnets = [
                s for s in block.subnets
                if s.status in [models.SubnetStatus.allocated, models.SubnetStatus.imported, models.SubnetStatus.reserved]
            ]
            used_ips = sum(ipaddress.ip_network(subnet.cidr).num_addresses for subnet in active_subnets)
            utilization = (used_ips / total_ips) * 100 if total_ips > 0 else 0

            # Get unique, active clients for the block
            clients = {subnet.client for subnet in active_subnets if subnet.client and subnet.client.is_active}

            free_ips = total_ips - used_ips
            block_stats.append({
                "block": block,
                "total_ips": total_ips,
                "used_ips": used_ips,
                "free_ips": free_ips,
                "utilization": utilization,
                "clients": clients
            })
        except ValueError:
            continue # Skip invalid CIDR in stats

    # --- Recent Allocations ---
    recent_allocations = db.query(models.Subnet).filter(
        models.Subnet.status.in_([models.SubnetStatus.allocated, models.SubnetStatus.imported, models.SubnetStatus.inactive])
    ).order_by(models.Subnet.created_at.desc()).limit(10).all()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request, "user": user, "block_stats": block_stats,
            "recent_allocations": recent_allocations, "vlan_count": vlan_count,
            "client_count": client_count
        }
    )



@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = crud.get_user_by_username(db, username)
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"}, status_code=400)
    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=303)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)

@app.get("/admin/users", response_class=HTMLResponse)
@admin_required
def admin_users(request: Request, db: Session = Depends(get_db)):
    admin = get_current_user(request, db)
    users = crud.get_users(db)
    return templates.TemplateResponse("admin.html", {"request": request, "users": users, "user": admin})

@app.post("/admin/users/create")
@admin_required
def admin_create_user(request: Request, username: str = Form(...), password: str = Form(...), level: int = Form(...), is_admin: bool = Form(False), db: Session = Depends(get_db)):
    if crud.get_user_by_username(db, username):
        raise HTTPException(status_code=400, detail="Username already exists")
    crud.create_user(db, username, password, level, is_admin)
    return RedirectResponse("/admin/users", status_code=303)


@app.get("/admin/users/{user_id}/change-password", response_class=HTMLResponse)
@admin_required
def change_password_page(request: Request, user_id: int, db: Session = Depends(get_db)):
    user_to_edit = db.query(models.User).filter(models.User.id == user_id).first()
    if not user_to_edit:
        raise HTTPException(status_code=404, detail="User not found")

    return templates.TemplateResponse(
        "change_password.html",
        {"request": request, "user": get_current_user(request, db), "user_to_edit": user_to_edit, "error": None}
    )

@app.post("/admin/users/{user_id}/change-password")
@admin_required
def change_password_action(
    request: Request,
    user_id: int,
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
):
    user_to_edit = db.query(models.User).filter(models.User.id == user_id).first()
    if not user_to_edit:
        raise HTTPException(status_code=404, detail="User not found")

    if new_password != confirm_password:
        return templates.TemplateResponse(
            "change_password.html",
            {
                "request": request,
                "user": get_current_user(request, db),
                "user_to_edit": user_to_edit,
                "error": "Passwords do not match."
            },
            status_code=400
        )

    user_to_edit.password_hash = hash_password(new_password)
    db.commit()

    return RedirectResponse(url="/admin/users", status_code=303)


@app.get("/admin/users/{user_id}/edit", response_class=HTMLResponse)
@admin_required
def edit_user_page(request: Request, user_id: int, db: Session = Depends(get_db)):
    user_to_edit = db.query(models.User).filter(models.User.id == user_id).first()
    if not user_to_edit:
        raise HTTPException(status_code=404, detail="User not found")

    all_blocks = db.query(models.IPBlock).order_by(models.IPBlock.cidr).all()
    user_block_ids = {block.id for block in user_to_edit.allowed_blocks}

    return templates.TemplateResponse(
        "edit_user.html",
        {
            "request": request,
            "user": get_current_user(request, db),
            "user_to_edit": user_to_edit,
            "all_blocks": all_blocks,
            "user_block_ids": user_block_ids,
        }
    )

@app.post("/admin/users/{user_id}/edit")
@admin_required
def edit_user_action(
    request: Request,
    user_id: int,
    level: int = Form(...),
    is_admin: bool = Form(False),
    allowed_blocks: List[int] = Form([]),
    db: Session = Depends(get_db),
):
    user_to_edit = db.query(models.User).filter(models.User.id == user_id).first()
    if not user_to_edit:
        raise HTTPException(status_code=404, detail="User not found")

    user_to_edit.level = level
    user_to_edit.is_admin = is_admin

    # Update allowed blocks
    user_to_edit.allowed_blocks.clear()
    if allowed_blocks:
        blocks = db.query(models.IPBlock).filter(models.IPBlock.id.in_(allowed_blocks)).all()
        for block in blocks:
            user_to_edit.allowed_blocks.append(block)

    db.commit()

    return RedirectResponse(url="/admin/users", status_code=303)


@app.get("/admin/blocks")
def admin_blocks(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    blocks = db.query(models.IPBlock).all()

    return templates.TemplateResponse(
        "admin_blocks.html",
        {"request": request, "user": user, "blocks": blocks}
    )



@app.post("/admin/blocks/create")
@admin_required
def create_block(
    request: Request,
    cidr: str = Form(...),
    description: str = Form(None),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)

    # Create the new block
    new_block = models.IPBlock(
        cidr=cidr,
        description=description,
        created_by=user.username,
        created_at=datetime.utcnow()
    )
    db.add(new_block)
    db.commit()
    db.refresh(new_block)

    # --- Automatic Re-assignment Logic ---
    try:
        new_parent_network = ipaddress.ip_network(new_block.cidr)
        unassigned_block = db.query(models.IPBlock).filter(models.IPBlock.cidr == "Unassigned").first()

        if unassigned_block:
            subnets_to_reassign = db.query(models.Subnet).filter(models.Subnet.block_id == unassigned_block.id).all()
            for subnet in subnets_to_reassign:
                try:
                    subnet_network = ipaddress.ip_network(subnet.cidr)
                    if subnet_network.subnet_of(new_parent_network):
                        subnet.block_id = new_block.id
                        # Also update status from inactive to imported
                        if subnet.status == models.SubnetStatus.inactive:
                            subnet.status = models.SubnetStatus.imported
                except ValueError:
                    continue # Skip invalid subnet CIDRs
            db.commit()
    except ValueError:
        pass # Ignore if the new block has an invalid CIDR
    except Exception as e:
        db.rollback()
        # Optionally log the error, e.g., print(f"Error during re-assignment: {e}")

    return RedirectResponse(url="/admin/blocks", status_code=303)


@app.get("/admin/blocks/{block_id}/edit", response_class=HTMLResponse)
@admin_required
def edit_block_page(request: Request, block_id: int, db: Session = Depends(get_db)):
    block = db.query(models.IPBlock).filter(models.IPBlock.id == block_id).first()
    if not block:
        raise HTTPException(status_code=404, detail="IP Block not found")
    return templates.TemplateResponse("edit_block.html", {"request": request, "user": get_current_user(request, db), "block": block})

@app.post("/admin/blocks/{block_id}/edit")
@admin_required
def edit_block_action(request: Request, block_id: int, description: str = Form(""), db: Session = Depends(get_db)):
    block = db.query(models.IPBlock).filter(models.IPBlock.id == block_id).first()
    if not block:
        raise HTTPException(status_code=404, detail="IP Block not found")
    block.description = description
    db.commit()
    return RedirectResponse(url="/admin/blocks", status_code=303)

@app.post("/admin/blocks/{block_id}/delete")
@admin_required
def delete_block_action(request: Request, block_id: int, db: Session = Depends(get_db)):
    block = db.query(models.IPBlock).filter(models.IPBlock.id == block_id).first()
    if not block:
        raise HTTPException(status_code=404, detail="IP Block not found")

    # Cascading delete of subnets within this block
    db.query(models.Subnet).filter(models.Subnet.block_id == block_id).delete(synchronize_session=False)

    db.delete(block)
    db.commit()
    return RedirectResponse(url="/admin/blocks", status_code=303)

# --- Client Management ---
@app.get("/admin/clients", response_class=HTMLResponse)
@admin_required
def admin_clients_page(request: Request, db: Session = Depends(get_db), query: Optional[str] = None):
    user = get_current_user(request, db)
    clients_query = db.query(models.Client)
    if query:
        clients_query = clients_query.filter(models.Client.name.ilike(f"%{query}%"))
    clients = clients_query.order_by(models.Client.name).all()
    return templates.TemplateResponse("admin_clients.html", {"request": request, "user": user, "clients": clients, "query": query})

@app.post("/admin/clients/create")
@admin_required
def create_client_action(request: Request, name: str = Form(...), db: Session = Depends(get_db)):
    crud.get_or_create_client(db, name=name, is_active=True)
    return RedirectResponse(url="/admin/clients", status_code=303)

@app.post("/admin/clients/bulk_action")
@admin_required
def client_bulk_action(request: Request, action: str = Form(...), selected_clients: List[int] = Form([]), db: Session = Depends(get_db)):
    if not selected_clients:
        return RedirectResponse(url="/admin/clients", status_code=303) # Or show a message

    clients_query = db.query(models.Client).filter(models.Client.id.in_(selected_clients))

    if action == "delete":
        for client in clients_query.all():
            # Unlink subnets before deleting client
            db.query(models.Subnet).filter(models.Subnet.client_id == client.id).update({"client_id": None})
            db.delete(client)
    elif action == "activate":
        clients_query.update({"is_active": True})
    elif action == "deactivate":
        clients_query.update({"is_active": False})

    db.commit()
    return RedirectResponse(url="/admin/clients", status_code=303)

@app.post("/admin/clients/{client_id}/toggle_status")
@admin_required
def toggle_client_status(request: Request, client_id: int, db: Session = Depends(get_db)):
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    client.is_active = not client.is_active
    db.commit()
    return RedirectResponse(url="/admin/clients", status_code=303)

@app.post("/admin/clients/{client_id}/delete")
@admin_required
def delete_client_action(request: Request, client_id: int, db: Session = Depends(get_db)):
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    # Unlink subnets before deleting client
    db.query(models.Subnet).filter(models.Subnet.client_id == client.id).update({"client_id": None})
    db.delete(client)
    db.commit()
    return RedirectResponse(url="/admin/clients", status_code=303)

@app.get("/clients/{client_id}", response_class=HTMLResponse)
@login_required
def client_detail_page(request: Request, client_id: int, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    subnets = db.query(models.Subnet).filter(models.Subnet.client_id == client.id).all()
    nat_ips = db.query(models.NatIp).filter(models.NatIp.client_id == client.id).all()

    return templates.TemplateResponse("client_detail.html", {
        "request": request, "user": user, "client": client,
        "subnets": subnets, "nat_ips": nat_ips
    })


# --- NAT IPs ---
@app.get("/dashboard/nat_ips", response_class=HTMLResponse)
@login_required
def nat_ips_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    nat_ips = db.query(models.NatIp).join(models.Client).order_by(models.Client.name).all()
    return templates.TemplateResponse("nat_ips.html", {"request": request, "user": user, "nat_ips": nat_ips})


# --- Search ---
@app.get("/dashboard/search", response_class=HTMLResponse)
@login_required
def search_results_page(request: Request, query: str, db: Session = Depends(get_db)):
    user = get_current_user(request, db)

    # Search Clients
    clients = db.query(models.Client).filter(models.Client.name.ilike(f"%{query}%")).all()

    # Search Subnets and IPs
    subnets_data = []
    try:
        # Check if query is an IP address, then find its containing subnet
        ip_addr = ipaddress.ip_address(query)
        all_subnets = db.query(models.Subnet).all()
        found_subnets = [s for s in all_subnets if ip_addr in ipaddress.ip_network(s.cidr)]
    except ValueError:
        # If not an IP, search by CIDR or description
        found_subnets = db.query(models.Subnet).filter(
            or_(
                models.Subnet.cidr.ilike(f"%{query}%"),
                models.Subnet.description.ilike(f"%{query}%")
            )
        ).all()

    for subnet in found_subnets:
        try:
            network = ipaddress.ip_network(subnet.cidr)
            hosts = list(network.hosts())
            subnets_data.append({
                "subnet": subnet,
                "broadcast": network.broadcast_address,
                "usable_range": f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A"
            })
        except (ValueError, IndexError):
            subnets_data.append({"subnet": subnet, "broadcast": "N/A", "usable_range": "N/A"})


    # Search VLANs
    vlan_filter = [models.VLAN.name.ilike(f"%{query}%")]
    if query.isdigit():
        vlan_filter.append(models.VLAN.vlan_id == int(query))
    vlans = db.query(models.VLAN).filter(or_(*vlan_filter)).all()

    return templates.TemplateResponse("search_results.html", {
        "request": request, "user": user, "query": query,
        "clients": clients, "subnets": subnets_data, "vlans": vlans
    })


@app.get("/admin/settings", response_class=HTMLResponse)
@admin_required
def settings_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)

    company_name_setting = db.query(models.Setting).filter(models.Setting.key == "company_name").first()
    logo_setting = db.query(models.Setting).filter(models.Setting.key == "logo_path").first()

    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "user": user,
            "company_name": company_name_setting.value if company_name_setting else "",
            "logo_path": logo_setting.value if logo_setting else None,
        }
    )

@app.post("/admin/settings")
@admin_required
async def settings_update(
    request: Request,
    company_name: str = Form(""),
    logo: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
):
    # Update company name
    name_setting = db.query(models.Setting).filter(models.Setting.key == "company_name").first()
    if not name_setting:
        name_setting = models.Setting(key="company_name", value=company_name)
        db.add(name_setting)
    else:
        name_setting.value = company_name

    # Handle logo upload
    if logo and logo.filename:
        # Save the logo to the static directory
        logo_path = f"static/logo-{logo.filename}"
        with open(logo_path, "wb") as buffer:
            shutil.copyfileobj(logo.file, buffer)

        # Save the path to the database
        logo_setting = db.query(models.Setting).filter(models.Setting.key == "logo_path").first()
        if not logo_setting:
            logo_setting = models.Setting(key="logo_path", value=logo_path)
            db.add(logo_setting)
        else:
            logo_setting.value = logo_path

    db.commit()

    return RedirectResponse(url="/admin/settings", status_code=303)

@app.post("/admin/settings/generate_logo")
@admin_required
def generate_logo_action(
    request: Request,
    logo_text: str = Form(...),
    background_color: str = Form(...),
    effect: str = Form(...),
    db: Session = Depends(get_db),
):
    width, height = 1200, 250
    hex_color = background_color.lstrip('#')
    bg_rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    img = Image.new("RGB", (width, height), bg_rgb)
    draw = ImageDraw.Draw(img)

    # --- Dynamic Font Sizing ---
    font_size = 150
    font = ImageFont.load_default(size=font_size)

    text_bbox = draw.textbbox((0, 0), logo_text, font=font)
    text_width = text_bbox[2] - text_bbox[0]

    while text_width > (width - 80) and font_size > 20:
        font_size -= 5
        font = ImageFont.load_default(size=font_size)
        text_bbox = draw.textbbox((0, 0), logo_text, font=font)
        text_width = text_bbox[2] - text_bbox[0]

    text_height = text_bbox[3] - text_bbox[1]
    x = (width - text_width) / 2
    y = (height - text_height) / 2

    # --- Improved Effect Colors ---
    shadow_color = tuple(max(0, c - 40) for c in bg_rgb)
    highlight_color = tuple(min(255, c + 40) for c in bg_rgb)
    text_color = (255, 255, 255)

    if effect == "engrave":
        draw.text((x + 2, y + 2), logo_text, font=font, fill=shadow_color)
        draw.text((x, y), logo_text, font=font, fill=highlight_color)
    elif effect == "emboss":
        draw.text((x - 2, y - 2), logo_text, font=font, fill=highlight_color)
        draw.text((x, y), logo_text, font=font, fill=shadow_color)
    else:  # "none"
        draw.text((x, y), logo_text, font=font, fill=text_color)

    logo_path = "static/generated-logo.png"
    img.save(logo_path, "PNG")

    logo_setting = db.query(models.Setting).filter(models.Setting.key == "logo_path").first()
    if not logo_setting:
        logo_setting = models.Setting(key="logo_path", value=logo_path)
        db.add(logo_setting)
    else:
        logo_setting.value = logo_path

    db.commit()

    return RedirectResponse(url="/admin/settings", status_code=303)


# GET - render VLAN form
@app.get("/dashboard/add_vlan")
def add_vlan(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    vlans = db.query(models.VLAN).all()  # Assuming you have a VLAN model
    return templates.TemplateResponse("add_vlan.html", {"request": request, "user": user, "vlans": vlans})

# POST - create VLAN
@app.post("/dashboard/add_vlan")
def add_vlan_post(
    request: Request,
    vlan_id: int = Form(...),
    name: str = Form(...),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    # Check for uniqueness
    if db.query(models.VLAN).filter(models.VLAN.vlan_id == vlan_id).first():
        raise HTTPException(status_code=400, detail=f"VLAN ID {vlan_id} already exists.")
    if db.query(models.VLAN).filter(models.VLAN.name == name).first():
        raise HTTPException(status_code=400, detail=f"VLAN name '{name}' already exists.")

    vlan = models.VLAN(
        vlan_id=vlan_id,
        name=name,
        created_by=user.username,
        created_at=datetime.utcnow()
    )
    db.add(vlan)
    db.commit()

    return RedirectResponse(url="/dashboard/add_vlan", status_code=303)

@app.get("/dashboard/vlans/{vlan_id}/edit", response_class=HTMLResponse)
@admin_required
def edit_vlan_page(request: Request, vlan_id: int, db: Session = Depends(get_db)):
    vlan = db.query(models.VLAN).filter(models.VLAN.id == vlan_id).first()
    if not vlan:
        raise HTTPException(status_code=404, detail="VLAN not found")
    return templates.TemplateResponse("edit_vlan.html", {"request": request, "user": get_current_user(request, db), "vlan": vlan})

@app.post("/dashboard/vlans/{vlan_id}/edit")
@admin_required
def edit_vlan_action(request: Request, vlan_id: int, name: str = Form(...), db: Session = Depends(get_db)):
    vlan = db.query(models.VLAN).filter(models.VLAN.id == vlan_id).first()
    if not vlan:
        raise HTTPException(status_code=404, detail="VLAN not found")

    # Check for uniqueness
    existing_vlan = db.query(models.VLAN).filter(models.VLAN.name == name).first()
    if existing_vlan and existing_vlan.id != vlan_id:
        raise HTTPException(status_code=400, detail=f"VLAN name '{name}' already exists.")

    vlan.name = name
    db.commit()
    return RedirectResponse(url="/dashboard/add_vlan", status_code=303)

@app.post("/dashboard/vlans/{vlan_id}/delete")
@admin_required
def delete_vlan_action(request: Request, vlan_id: int, db: Session = Depends(get_db)):
    vlan = db.query(models.VLAN).filter(models.VLAN.id == vlan_id).first()
    if not vlan:
        raise HTTPException(status_code=404, detail="VLAN not found")

    # Check if VLAN is in use
    if db.query(models.Subnet).filter(models.Subnet.vlan_id == vlan.id).first():
        raise HTTPException(status_code=400, detail="Cannot delete a VLAN that is currently in use by a subnet.")

    db.delete(vlan)
    db.commit()
    return RedirectResponse(url="/dashboard/add_vlan", status_code=303)


@app.get("/dashboard/allocations/{subnet_id}/edit", response_class=HTMLResponse)
@admin_required
def edit_allocation_page(request: Request, subnet_id: int, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    subnet = db.query(models.Subnet).filter(models.Subnet.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")

    vlans = db.query(models.VLAN).order_by(models.VLAN.vlan_id).all()

    return templates.TemplateResponse(
        "edit_allocation.html",
        {
            "request": request,
            "user": user,
            "subnet": subnet,
            "vlans": vlans,
        }
    )

@app.post("/dashboard/allocations/{subnet_id}/edit")
@admin_required
def edit_allocation_action(
    request: Request,
    subnet_id: int,
    description: str = Form(...),
    vlan_id: Optional[int] = Form(None),
    db: Session = Depends(get_db),
):
    subnet = db.query(models.Subnet).filter(models.Subnet.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")

    subnet.description = description
    subnet.vlan_id = vlan_id
    db.commit()

    return RedirectResponse(url="/", status_code=303)

@app.post("/dashboard/allocations/{subnet_id}/deactivate")
@admin_required
def deactivate_allocation_action(
    request: Request,
    subnet_id: int,
    db: Session = Depends(get_db),
):
    subnet = db.query(models.Subnet).filter(models.Subnet.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")

    subnet.status = models.SubnetStatus.deactivated
    db.commit()

    return RedirectResponse(url="/", status_code=303)


@app.get("/dashboard/churned", response_class=HTMLResponse)
@admin_required
def churned_allocations_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    churned_allocations = db.query(models.Subnet).filter(
        models.Subnet.status == models.SubnetStatus.deactivated
    ).order_by(models.Subnet.created_at.desc()).all()

    return templates.TemplateResponse(
        "churned_allocations.html",
        {
            "request": request,
            "user": user,
            "allocations": churned_allocations,
        }
    )

@app.post("/dashboard/allocations/{subnet_id}/reactivate")
@admin_required
def reactivate_allocation_action(
    request: Request,
    subnet_id: int,
    db: Session = Depends(get_db),
):
    subnet = db.query(models.Subnet).filter(models.Subnet.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")

    subnet.status = models.SubnetStatus.allocated
    db.commit()

    return RedirectResponse(url="/dashboard/churned", status_code=303)


@app.post("/dashboard/allocations/{subnet_id}/activate")
@level_required(2)
def activate_allocation_action(
    request: Request,
    subnet_id: int,
    db: Session = Depends(get_db),
):
    subnet = db.query(models.Subnet).filter(models.Subnet.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")

    subnet.status = models.SubnetStatus.allocated
    db.commit()

    return RedirectResponse(url="/", status_code=303)

@app.post("/dashboard/allocations/{subnet_id}/delete")
@admin_required
def delete_subnet_permanently(request: Request, subnet_id: int, db: Session = Depends(get_db)):
    """ Permanently deletes a subnet, e.g., from the churned page. """
    subnet = db.query(models.Subnet).filter(models.Subnet.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")

    # Also delete associated interface addresses
    db.query(models.InterfaceAddress).filter(models.InterfaceAddress.subnet_id == subnet_id).delete(synchronize_session=False)

    db.delete(subnet)
    db.commit()
    return RedirectResponse(url="/dashboard/churned", status_code=303)
