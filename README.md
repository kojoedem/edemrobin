# IP DB (Starter)

A FastAPI + SQLite app for managing IP allocations with roles and an admin dashboard.

## Features
- Login required
- Roles/levels:
  - Level 1: view VLAN & IP allocations
  - Level 2: allocate subnets (from base block)
  - Level 3: (example) admin, plus `is_admin` flag for admin routes
- Admin dashboard to create users and set levels
- Tracks creator and timestamp
- Prevents overlapping allocations by picking next free subnet from the base block

## Quickstart
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

uvicorn app:app --reload
```

Visit:
- Login: http://127.0.0.1:8000/login
- App: http://127.0.0.1:8000/
- Admin: http://127.0.0.1:8000/admin/users

**Default admin:** `admin / admin123` (change immediately).

## Notes
- Tailwind is included via CDN in templates for simplicity.
- Base block is currently hardcoded as `192.168.1.0/24` in `app.py` (set `BASE_BLOCK`).
- This is a starter; add CSRF protection, password reset, and user management (edit/delete) before production.
