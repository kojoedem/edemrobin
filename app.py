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

@app.get("/")
def home(request: Request, block_id: Optional[int] = None, db: Session = Depends(get_db)):
    user = get_current_user(request, db)

    # Get blocks this user is allowed to see for the stats cards
    if user.is_admin:
        blocks_for_stats = db.query(models.IPBlock).filter(models.IPBlock.cidr != 'Unassigned').order_by(models.IPBlock.cidr).all()
    else:
        blocks_for_stats = [b for b in user.allowed_blocks if b.cidr != 'Unassigned']
        blocks_for_stats.sort(key=lambda x: ipaddress.ip_network(x.cidr))

    block_stats = []
    for block in blocks_for_stats:
        parent_network = ipaddress.ip_network(block.cidr)
        total_ips = parent_network.num_addresses

        used_ips = 0
        # Filter subnets by status to not include 'imported' or 'inactive' as 'used' in the main stat
        active_subnets = [s for s in block.subnets if s.status == models.SubnetStatus.allocated]
        for subnet in active_subnets:
            used_ips += ipaddress.ip_network(subnet.cidr).num_addresses

        block_stats.append({
            "block": block,
            "total_ips": total_ips,
            "used_ips": used_ips,
            "utilization": (used_ips / total_ips) * 100 if total_ips > 0 else 0,
        })

    # Fetch allocations for a specific block if block_id is provided
    allocations = []
    selected_block = None
    if block_id:
        selected_block = db.query(models.IPBlock).filter(models.IPBlock.id == block_id).first()
        if selected_block:
            # Check if the user has permission to view this block
            if user.is_admin or selected_block in user.allowed_blocks:
                allocations = db.query(models.Subnet).filter(
                    models.Subnet.block_id == block_id,
                    models.Subnet.status != models.SubnetStatus.deactivated
                ).order_by(models.Subnet.created_at.desc()).all()

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "allocations": allocations,
            "block_stats": block_stats,
            "selected_block": selected_block,
        }
    )


@app.post("/allocate")
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

    try:
        new_subnet = allocate_subnet(
            db,
            block_id=block_id,
            user=user,
            subnet_size=subnet_size,
            vlan_id=vlan_id,
            description=final_description
        )
    except HTTPException as e:
        # You can pass the error message to the template
        # For now, just re-raise
        raise e

    return RedirectResponse("/dashboard/allocate_ip", status_code=303)

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

    block = models.IPBlock(
        cidr=cidr,
        description=description,
        created_by=user.username,
        created_at=datetime.utcnow()
    )
    db.add(block)
    db.commit()
    db.refresh(block)

    # Redirect back to the blocks page
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

    if block.subnets:
        # Prevent deletion if there are subnets associated with this block
        # You might want to handle this more gracefully with a message to the user
        raise HTTPException(status_code=400, detail="Cannot delete a block that has subnets allocated from it.")

    db.delete(block)
    db.commit()
    return RedirectResponse(url="/admin/blocks", status_code=303)


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
@app.get("/dashboard/search_vlan")
def search_vlan(request: Request, query: Optional[str] = None, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    results = []
    if query:
        search_query = query.strip()
        # Search by name OR by ID if the query is a valid integer
        from sqlalchemy import or_
        q_filter = [models.VLAN.name.contains(search_query)]
        if search_query.isdigit():
            q_filter.append(models.VLAN.vlan_id == int(search_query))

        results = db.query(models.VLAN).filter(or_(*q_filter)).all()

    return templates.TemplateResponse(
        "search_vlan.html",
        {"request": request, "user": user, "results": results, "query": query}
    )

@app.get("/dashboard/search_ip")
def search_ip(request: Request, query: Optional[str] = None, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    results = []
    search_type = None
    error = None
    searched_ip_str = None

    if query:
        try:
            searched_ip = ipaddress.ip_address(query)
            searched_ip_str = str(searched_ip)
            search_type = 'ip'

            all_subnets = db.query(models.Subnet).all()
            found_subnets = [s for s in all_subnets if searched_ip in ipaddress.ip_network(s.cidr)]

            for subnet in found_subnets:
                network = ipaddress.ip_network(subnet.cidr)
                usable_hosts = list(network.hosts())
                results.append({
                    "type": "subnet",
                    "data": {
                        "subnet": subnet,
                        "network_address": network.network_address,
                        "broadcast_address": network.broadcast_address,
                        "total_ips": network.num_addresses,
                        "usable_ips_count": len(usable_hosts),
                        "usable_range": f"{usable_hosts[0]} - {usable_hosts[-1]}" if usable_hosts else "N/A",
                        "all_usable_ips": usable_hosts,
                    }
                })

        except ValueError:
            search_type = 'text'
            from sqlalchemy import or_

            found_subnets = db.query(models.Subnet).filter(
                or_(models.Subnet.cidr.contains(query), models.Subnet.description.contains(query))
            ).all()
            for subnet in found_subnets:
                results.append({"type": "subnet", "data": {"subnet": subnet}})

            found_blocks = db.query(models.IPBlock).filter(
                or_(models.IPBlock.cidr.contains(query), models.IPBlock.description.contains(query))
            ).all()
            for block in found_blocks:
                results.append({"type": "block", "data": block})

        if not results:
            error = f"No results found for '{query}'."

    return templates.TemplateResponse(
        "search_ip.html",
        {
            "request": request,
            "user": user,
            "results": results,
            "query": query,
            "search_type": search_type,
            "searched_ip": searched_ip_str,
            "error": error,
        }
    )
@app.get("/dashboard/allocate_ip", response_class=HTMLResponse)
def allocate_ip_page(request: Request, db: Session = Depends(get_db)):
    """
    Renders the page for allocating new subnets.
    """
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    # Fetch data needed for the form
    allocations = db.query(models.Subnet).filter(
        models.Subnet.status != models.SubnetStatus.deactivated
    ).order_by(models.Subnet.created_at.desc()).all()

    if user.is_admin:
        blocks = db.query(models.IPBlock).order_by(models.IPBlock.cidr).all()
    else:
        blocks = user.allowed_blocks
        blocks.sort(key=lambda x: ipaddress.ip_network(x.cidr))

    vlans = db.query(models.VLAN).order_by(models.VLAN.vlan_id).all()

    return templates.TemplateResponse(
        "allocate_ip.html",
        {
            "request": request,
            "user": user,
            "allocations": allocations,
            "blocks": blocks,
            "vlans": vlans,
        },
    )


@app.get("/dashboard/allocations/{subnet_id}/edit", response_class=HTMLResponse)
@admin_required
def edit_allocation_page(request: Request, subnet_id: int, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    subnet = db.query(models.Subnet).filter(models.Subnet.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")

    vlans = db.query(models.VLAN).order_by(models.VLAN.vlan_id).all()
    blocks = db.query(models.IPBlock).order_by(models.IPBlock.cidr).all()

    return templates.TemplateResponse(
        "edit_allocation.html",
        {
            "request": request,
            "user": user,
            "subnet": subnet,
            "vlans": vlans,
            "blocks": blocks,
        }
    )

@app.post("/dashboard/allocations/{subnet_id}/edit")
@admin_required
def edit_allocation_action(
    request: Request,
    subnet_id: int,
    description: str = Form(...),
    vlan_id: Optional[int] = Form(None),
    block_id: int = Form(...),
    db: Session = Depends(get_db),
):
    subnet = db.query(models.Subnet).filter(models.Subnet.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")

    # Also check if the new block exists
    new_block = db.query(models.IPBlock).filter(models.IPBlock.id == block_id).first()
    if not new_block:
        raise HTTPException(status_code=404, detail="Parent block not found")

    subnet.description = description
    subnet.vlan_id = vlan_id
    subnet.block_id = block_id

    # If moving to a real block from unassigned, mark as allocated
    if subnet.status == models.SubnetStatus.inactive and new_block.cidr != "Unassigned":
        subnet.status = models.SubnetStatus.allocated

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


@app.get("/dashboard/upload_config/export")
def export_config_csv(
    request: Request,
    filename: str,
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    safe_name = os.path.basename(filename)
    path = os.path.join("configs", safe_name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Uploaded file not found")

    with open(path, "r") as f:
        config_text = f.read()
    interfaces = parse_config(config_text)

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["interface_name", "ip_address", "subnet_mask", "description", "vlan_id"])
    for iface in interfaces:
        w.writerow([iface.get(k) for k in ["name", "ip_address", "subnet_mask", "description", "vlan_id"]])
    out_name = f"{os.path.splitext(safe_name)[0]}_interfaces.csv"
    buf.seek(0)
    headers = {"Content-Disposition": f'attachment; filename="{out_name}"'}
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers=headers)

@app.post("/dashboard/upload_config/save")
@admin_required
def save_config_to_db(request: Request, filename: str = Form(...), db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    safe_name = os.path.basename(filename)
    path = os.path.join("configs", safe_name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Uploaded file not found")

    with open(path, "r") as f:
        config_text = f.read()
    interfaces = parse_config(config_text)

    for iface in interfaces:
        try:
            # Use /32 for each IP to mark it as used
            network = ipaddress.ip_network(f"{iface['ip_address']}/32")
            # The parent block is derived from the IP and its actual mask
            parent_network = ipaddress.ip_network(f"{iface['ip_address']}/{iface['subnet_mask']}", strict=False)
        except (ValueError, TypeError):
            continue

        block = crud.get_or_create_block(db, str(parent_network), created_by=user.username)

        vlan = None
        if iface.get('vlan_id'):
            vlan_id = iface['vlan_id']
            vlan = crud.get_vlan_by_id(db, vlan_id)
            if not vlan:
                # If VLAN with this ID doesn't exist, create it.
                vlan_name = iface.get('name', f"VLAN_{vlan_id}")

                # To prevent creating a VLAN with a duplicate name, check first.
                existing_vlan_by_name = db.query(models.VLAN).filter(models.VLAN.name == vlan_name).first()
                if existing_vlan_by_name:
                    print(f"Warning: A VLAN with the name '{vlan_name}' already exists but with a different ID. Skipping VLAN creation for this interface to avoid conflicts.")
                else:
                    try:
                        vlan = crud.create_vlan(db, vlan_id=vlan_id, name=vlan_name, created_by=user.username)
                    except Exception as e:
                        print(f"Error creating VLAN {vlan_id}: {e}")
                        # Potentially a race condition if another process created it.
                        db.rollback()
                        vlan = crud.get_vlan_by_id(db, vlan_id)

        description = iface['description'] or f"Imported from {iface.get('name', 'config')}"

        # Use a /32 for the subnet to represent a single used IP
        subnet_cidr = f"{iface['ip_address']}/32"

        existing_subnet = db.query(models.Subnet).filter(models.Subnet.cidr == subnet_cidr).first()
        if not existing_subnet:
            crud.create_or_get_subnet(
                db=db,
                cidr=subnet_cidr,
                block=block,
                status=models.SubnetStatus.imported,
                created_by=user.username,
                vlan_id=vlan.id if vlan else None,
                description=description,
            )

    return RedirectResponse(url="/", status_code=303)


from fastapi import File, UploadFile

os.makedirs("configs", exist_ok=True)

@app.get("/dashboard/upload_config", response_class=HTMLResponse)
@admin_required
def upload_config_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("upload_config.html", {"request": request, "user": user})

@app.post("/dashboard/upload_config")
@admin_required
async def upload_config_action(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    content = await file.read()
    config_text = content.decode("utf-8")

    filepath = f"configs/{file.filename}"
    with open(filepath, "w") as f:
        f.write(config_text)

    interfaces = parse_config(config_text)

    return templates.TemplateResponse(
        "upload_result.html",
        {
            "request": request,
            "user": user,
            "interfaces": interfaces,
            "filename": file.filename,
        }
    )
