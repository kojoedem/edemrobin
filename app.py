from fastapi import FastAPI, Depends, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional

import crud, models, schemas
from database import engine, SessionLocal
from ip_allocator import allocate_subnet
from security import verify_password, hash_password, login_required, level_required, get_current_user, admin_required

models.Base.metadata.create_all(bind=engine)

# Create default admin if not present
with SessionLocal() as db:
    if crud.count_users(db) == 0:
        crud.create_user(db, username="admin", password="admin123", level=3, is_admin=True)

app = FastAPI(title="IP DB")

# IMPORTANT: change this to a strong random secret in production
app.add_middleware(SessionMiddleware, secret_key="change_this_secret")

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

BASE_BLOCK = "192.168.1.0/24"  # You can make this configurable later

@app.get("/", response_class=HTMLResponse)
@login_required
def home(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    ips = crud.get_ips(db)
    return templates.TemplateResponse("index.html", {"request": request, "ips": ips, "user": user, "base_block": BASE_BLOCK})

@app.post("/allocate")
@level_required(2)
def allocate_ip(
    request: Request,
    cidr: str = Form(...),
    vlan: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    new_subnet = allocate_subnet(BASE_BLOCK, cidr, crud.get_all_subnets(db))
    if not new_subnet:
        raise HTTPException(status_code=400, detail="No available subnet of requested size in base block")
    ip_entry = schemas.IPCreate(
        subnet=new_subnet,
        vlan=vlan,
        description=description,
        person=user.username,
        created_at=datetime.utcnow(),
    )
    crud.create_ip(db, ip_entry)
    return RedirectResponse("/", status_code=303)

# ---------- Auth ----------
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = crud.get_user_by_username(db, username=username)
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"}, status_code=400)
    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=303)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)

# ---------- Admin ----------
@app.get("/admin/users", response_class=HTMLResponse)
@admin_required
def admin_users(request: Request, db: Session = Depends(get_db)):
    admin = get_current_user(request, db)
    users = crud.get_users(db)
    return templates.TemplateResponse("admin_users.html", {"request": request, "users": users, "admin": admin})

@app.post("/admin/users/create")
@admin_required
def admin_create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    level: int = Form(...),
    is_admin: bool = Form(False),
    db: Session = Depends(get_db),
):
    if crud.get_user_by_username(db, username):
        raise HTTPException(status_code=400, detail="Username already exists")
    crud.create_user(db, username=username, password=password, level=level, is_admin=is_admin)
    return RedirectResponse("/admin/users", status_code=303)
