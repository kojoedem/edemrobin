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

    # fetch all IP allocations
    ips = db.query(models.IPAddress).all()

    # fetch base block (optional, if exists)
    base_block = db.query(models.IPBlock).first()
    base_block = base_block.cidr if base_block else "Not set"

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "ips": ips,            # ✅ ensure ips is passed

            "base_block": base_block,
        }
    )


@app.post("/allocate")
@level_required(2)
def allocate_ip(
    request: Request,
    block_id: int = Form(...),
    cidr: str = Form(...),
    vlan: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    new_subnet = allocate_subnet(db, block_id, user, subnet_size=int(cidr.strip("/")))
    if not new_subnet:
        raise HTTPException(status_code=400, detail="No available subnet")
    return RedirectResponse("/", status_code=303)

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
    if query:
        results = db.query(models.IP).filter(models.IP.subnet.contains(query)).all()

    return templates.TemplateResponse(
        "search_ip.html",
        {"request": request, "user": user, "results": results}
    )
# GET - show page
@app.get("/dashboard/allocate_ip")
def allocate_ip(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    ips = db.query(models.IP).all()
    return templates.TemplateResponse(
        "allocate_ip.html",
        {"request": request, "ips": ips, "user": user}
    )

# POST - allocate new IP
@app.post("/dashboard/allocate_ip")
def allocate_ip_post(
    request: Request,
    subnet: str = Form(...),
    vlan: str = Form(None),
    description: str = Form(None),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    new_ip = models.IP(
        subnet=subnet,
        vlan=vlan,
        description=description,
        person=user.username,   # 👈 Assigned By = current user
        created_at=datetime.utcnow()
    )
    db.add(new_ip)
    db.commit()

    return RedirectResponse(url="/dashboard/allocate_ip", status_code=303)


@app.get("/dashboard/upload_config")
def upload_config(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("upload_config.html", {"request": request, "user": user})


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

    ip_blocks, used_ips = parse_config(config_text)

    # build CSV
    buf = io.StringIO()
    w = csv.writer(buf)

    if view == "summary":
        # one row per block
        w.writerow(["block_cidr", "used_ip_count"])
        for block, ips in sorted(ip_blocks.items(), key=lambda x: x[0]):
            w.writerow([block, len(ips)])
        out_name = f"{os.path.splitext(safe_name)[0]}_blocks_summary.csv"
    else:
        # one row per IP
        w.writerow(["block_cidr", "ip"])
        for block, ips in sorted(ip_blocks.items(), key=lambda x: x[0]):
            for ip in ips:
                w.writerow([block, ip])
        out_name = f"{os.path.splitext(safe_name)[0]}_ip_list.csv"

    buf.seek(0)
    headers = {"Content-Disposition": f'attachment; filename="{out_name}"'}
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers=headers)


from fastapi import File, UploadFile
import os, re, ipaddress

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
    ip_blocks, used_ips = parse_config(config_text)

    return templates.TemplateResponse(
        "upload_result.html",
        {
            "request": request,
            "user": user,
            "ip_blocks": ip_blocks,
            "used_ips": used_ips,
            "filename": file.filename,
        }
    )
