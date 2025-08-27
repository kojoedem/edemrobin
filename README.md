# IPAM: IP Address Management

A web tool for managing IP addresses, subnets, VLANs, and clients, featuring role-based access and powerful network configuration import capabilities. Built with FastAPI, SQLAlchemy, and Jinja2.

---

## Key Features

-   **👤 User & Role Management:**
    -   Secure user authentication (login/logout).
    -   Admin panel for creating users, changing passwords, and assigning roles.
    -   **Level 1 (Viewer):** Can only view allocated subnets and VLANs.
    -   **Level 2 (Manager):** Can allocate and manage subnets and VLANs within their permitted blocks.
    -   **Admin:** Full control over users, roles, IP blocks, clients, and system settings.

-   **🌐 IP & Subnet Management:**
    -   Admins define parent IP blocks (e.g., `10.0.0.0/16`).
    -   Users are assigned access to specific blocks.
    -   Intelligent subnet allocation prevents overlaps and finds the next available CIDR of a requested size.
    -   Track subnet details including description, VLAN, and associated client.

-   **🏢 Client Management:**
    -   Create, view, and delete clients.
    -   Associate subnets and NAT IPs directly with clients for clear ownership tracking.
    -   Client detail pages provide a consolidated view of all associated network resources.

-   **🔌 Cisco Config Import:**
    -   Upload a Cisco router configuration file to bulk-import network information.
    -   **Multi-pass parsing** ensures robust and error-free import of complex configurations.
    -   Automatically creates Subnets, VLANs (using interface descriptions as names), and Clients.
    -   Intelligently sorts imported subnets into user-defined parent blocks.
    -   Subnets on `shutdown` interfaces are automatically marked as `deactivated`.
    -   Subnets that don't fit a specified parent block are placed in an "Unassigned" group for later review.

-   **🔍 NAT & Search:**
    -   Automatically parses `ip route` commands from configs to identify and track static NAT IPs for each client.
    -   Comprehensive search functionality to find any IP address and see which subnet it belongs to.
    -   Search for VLANs by ID or name.

-   **🔄 Churn Management:**
    -   Subnets can be "deactivated" instead of deleted, preserving historical allocation data.
    -   View and reactivate churned subnets from a dedicated page.

-   **⚙️ System Customization:**
    -   Admins can set a custom company name for the application header.
    -   Upload a custom company logo or use the built-in logo generator to create one from text.

---

## Project Structure

```
.
├── app.py              # Main FastAPI app, core routes (login, admin, dashboard)
├── crud.py             # Database CRUD (Create, Read, Update, Delete) functions
├── database.py         # SQLAlchemy engine and session setup
├── ip_allocator.py     # Core logic for finding and allocating available subnets
├── models.py           # SQLAlchemy database models
├── schemas.py          # Pydantic data validation schemas
├── security.py         # Auth helpers (password hashing, user sessions, permissions)
├── utils.py            # Utility functions (e.g., Cisco config parser)
├── routes_allocate.py  # FastAPI router for allocation-specific endpoints
├── routes_import.py    # FastAPI router for the config import process
├── routes_vlan.py      # FastAPI router for VLAN management
├── requirements.txt
├── static/             # Static files (CSS, images, etc.)
└── templates/          # Jinja2 HTML templates
```

---

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/ipdb.git
cd ipdb
```

### 2. Create and Activate Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
uvicorn app:app --reload
```
The application will be available at **http://127.0.0.1:8000**.

---

## Usage

1.  **First Run:** The application will automatically create a default administrator account on first startup:
    -   **Username:** `admin`
    -   **Password:** `admin123`
    -   **⚠️ It is critical to log in and change this password immediately.**

2.  **Admin Setup:**
    -   Log in as the admin.
    -   Navigate to **Admin -> Blocks** to create the parent IP blocks for your network.
    -   Navigate to **Admin -> Users** to create new user accounts and assign them roles and access to specific IP blocks.
    -   Navigate to **Admin -> Settings** to customize the application title and logo.

3.  **Importing Data (Optional but Recommended):**
    -   Navigate to **Dashboard -> Import Cisco Config**.
    -   Upload your router configuration file and specify the parent CIDR blocks you created.
    -   The system will parse the file and import all relevant subnets, VLANs, and clients.

4.  **Allocating Subnets:**
    -   Users with Level 2 or Admin privileges can navigate to **Dashboard -> Allocate IP/Subnet**.
    -   Select a parent block, choose a subnet size, and add a description to allocate a new subnet. The system will automatically find the next available one.