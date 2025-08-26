# IP DB - IP Address Management Tool

A small web tool for managing IP addresses, VLANs, and users with role-based access.  
Built with **FastAPI**, **SQLite**, and **Tailwind CSS**.

---

## Features
- 🔐 **Authentication**
  - Login & Logout
  - User registration (admin can assign role + IP block access)
- 👥 **Role-based Access**
  - **Level 1 (Viewer):** can only view IPs and VLANs
  - **Level 2 (Manager):** can allocate/generate IPs and VLANs
  - **Admin:** can manage users, roles, and IP blocks
- 🌐 **IP Address Management**
  - Admin defines one or more IP blocks (e.g. `192.168.1.0/24`)
  - Users can allocate subnetworks (e.g. `/30`, `/29`) without conflicts
  - Tracks VLANs (optional), description, user, and timestamp
- 📊 **Dashboard**
  - Left-hand navigation sidebar after login
  - Links to search IPs, VLANs, and manage resources

---

## Project Structure
ipdb/
│── app.py # Main FastAPI app
│── auth.py # Authentication (login, register, logout)
│── ip.py # IP allocation & management
│── admin.py # Admin-only routes (manage users, blocks)
│── models.py # Database models (User, IPBlock, Allocation, etc.)
│── database.py # Database session handling
│── templates/ # Jinja2 HTML templates
│ ├── base.html # Main layout (with sidebar)
│ ├── login.html # Login form
│ ├── register.html # Register form
│ ├── dashboard.html# Dashboard view
│── static/ # Tailwind CSS, JS
│── README.md # Project documentation
│── .gitignore # Git ignore file


---

## Installation

### 1. Clone repository
```bash
git clone https://github.com/yourusername/ipdb.git
cd ipdb


python3 -m venv venv
source venv/bin/activate


pip install -r requirements.txt


uvicorn app:app --reload

http://127.0.0.1:8000


## Usage

Go to /register to create your first user (or admin).

Admin can:

Add IP blocks

Assign which users can use which blocks

Promote users to Level 1 or Level 2

Normal users can log in at /login.

After login → access the dashboard at /dashboard.


## Roles

Admin

Manage users, roles, and IP blocks

Full access

Level 2 (Manager)

Allocate/generate IPs and VLANs from allowed blocks

Level 1 (Viewer)

Only view IPs and VLANs



To Do / Next Steps
Add search functionality for IPs & VLANs
Add audit logs (track who created/edited what)
Export IP usage as CSV/Excel
Add frontend enhancements (Tailwind UI components)


# UPDATED LOGIC
I have updated this phase so it can handle router config upload and csv downlaod.