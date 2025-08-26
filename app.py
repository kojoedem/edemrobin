from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional
import os, re, ipaddress, io, csv
from starlette.responses import StreamingResponse

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
def home(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)

    # Fetch all allocated subnets for the main table
    allocations = db.query(models.Subnet).order_by(models.Subnet.created_at.desc()).all()

    # Calculate utilization stats for each parent block
    blocks = db.query(models.IPBlock).all()
    block_stats = []
    for block in blocks:
        parent_network = ipaddress.ip_network(block.cidr)
        total_ips = parent_network.num_addresses

        used_ips = 0
        for subnet in block.subnets:
            used_ips += ipaddress.ip_network(subnet.cidr).num_addresses

        block_stats.append({
            "block": block,
            "total_ips": total_ips,
            "used_ips": used_ips,
            "available_ips": total_ips - used_ips,
            "utilization": (used_ips / total_ips) * 100 if total_ips > 0 else 0,
        })

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "allocations": allocations,
            "block_stats": block_stats,
        }
    )


@app.post("/allocate")
@level_required(2)
def allocate_ip_action(
    request: Request,
    block_id: int = Form(...),
    subnet_size: int = Form(...),
    vlan_id: Optional[int] = Form(None),
    description: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    try:
        new_subnet = allocate_subnet(
            db,
            block_id=block_id,
            user=user,
            subnet_size=subnet_size,
            vlan_id=vlan_id,
            description=description
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

    vlan = models.VLAN(
        vlan_id=vlan_id,
        name=name,
        created_by=user.username,
        created_at=datetime.utcnow()
    )
    db.add(vlan)
    db.commit()

    return RedirectResponse(url="/dashboard/add_vlan", status_code=303)
@app.get("/dashboard/search_vlan")
def search_vlan(request: Request, query: Optional[str] = None, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    results = []
    if query:
        results = db.query(models.VLAN).filter(models.VLAN.vlan_id.contains(query)).all()

    return templates.TemplateResponse(
        "search_vlan.html",
        {"request": request, "user": user, "results": results}
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
            # Try to parse the query as an IP address
            searched_ip = ipaddress.ip_address(query)
            searched_ip_str = str(searched_ip)
            search_type = 'ip'

            all_subnets = db.query(models.Subnet).all()
            found_subnets = []
            for subnet in all_subnets:
                if searched_ip in ipaddress.ip_network(subnet.cidr):
                    found_subnets.append(subnet)

            if found_subnets:
                for subnet in found_subnets:
                    network = ipaddress.ip_network(subnet.cidr)
                    usable_hosts = list(network.hosts())
                    results.append({
                        "subnet": subnet,
                        "network_address": network.network_address,
                        "broadcast_address": network.broadcast_address,
                        "total_ips": network.num_addresses,
                        "usable_ips_count": len(usable_hosts),
                        "usable_range": f"{usable_hosts[0]} - {usable_hosts[-1]}" if usable_hosts else "N/A",
                        "all_usable_ips": usable_hosts,
                    })

        except ValueError:
            # If it's not a valid IP, treat it as a text search
            search_type = 'text'
            from sqlalchemy import or_
            found_subnets = db.query(models.Subnet).filter(
                or_(
                    models.Subnet.cidr.contains(query),
                    models.Subnet.description.contains(query)
                )
            ).all()
            if found_subnets:
                for subnet in found_subnets:
                    results.append({"subnet": subnet}) # Simpler result for text search

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
    allocations = db.query(models.Subnet).order_by(models.Subnet.created_at.desc()).all()
    blocks = db.query(models.IPBlock).order_by(models.IPBlock.cidr).all()
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


@app.get("/dashboard/upload_config/export")
def export_config_csv(
    request: Request,
    filename: str,
    view: str = "detailed",             # "detailed" or "summary"
    db: Session = Depends(get_db),
):
    # require login
    user = get_current_user(request, db)

    # sanitize + locate file
    safe_name = os.path.basename(filename)
    path = os.path.join("configs", safe_name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Uploaded file not found")

    # read + parse
    with open(path, "r") as f:
        config_text = f.read()

    processed_blocks, _, _ = parse_config(config_text)

    # build CSV
    buf = io.StringIO()
    w = csv.writer(buf)

    if view == "summary":
        # one row per block
        w.writerow(["block_cidr", "used_ip_count", "available_ip_count", "total_ip_count"])
        for block in processed_blocks:
            w.writerow([block["block_cidr"], block["used_count"], block["available_count"], block["total_count"]])
        out_name = f"{os.path.splitext(safe_name)[0]}_blocks_summary.csv"
    else:
        # one row per IP
        w.writerow(["block_cidr", "ip"])
        for block in processed_blocks:
            for ip in block["used_ips"]:
                w.writerow([block["block_cidr"], ip])
        out_name = f"{os.path.splitext(safe_name)[0]}_ip_list.csv"

    buf.seek(0)
    headers = {"Content-Disposition": f'attachment; filename="{out_name}"'}
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers=headers)


from fastapi import File, UploadFile

# Make sure configs folder exists
os.makedirs("configs", exist_ok=True)

@app.get("/dashboard/upload_config")
def upload_config(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("upload_config.html", {"request": request, "user": user})

@app.post("/dashboard/upload_config")
async def upload_config_post(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    # Read uploaded file
    content = await file.read()
    config_text = content.decode("utf-8")

    # Save to configs folder
    filepath = f"configs/{file.filename}"
    with open(filepath, "w") as f:
        f.write(config_text)

    # Parse config
    processed_blocks, used_ips, invalid_entries = parse_config(config_text)

    return templates.TemplateResponse(
        "upload_result.html",
        {
            "request": request,
            "user": user,
            "processed_blocks": processed_blocks,
            "used_ips": used_ips,
            "invalid_entries": invalid_entries,
            "filename": file.filename,
        }
    )
