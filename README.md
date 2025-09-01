# 🌐 EDEMROBIN

[![FastAPI](https://img.shields.io/badge/Built%20With-FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com/)  
[![Database](https://img.shields.io/badge/Database-SQLite%20%7C%20Postgres%20%7C%20MySQL-blue?logo=postgresql&logoColor=white)]()  
[![TailwindCSS](https://img.shields.io/badge/UI-TailwindCSS-38B2AC?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)  

**EDEMROBIN** is a lightweight web tool for managing IP addresses, VLANs, and users with role-based access control.  
Built with **FastAPI** and **Tailwind CSS**, with database support for **SQLite (default)** or **PostgreSQL/MySQL (production)**.  

Unlike traditional IPAM tools, EDEMROBIN lets you **upload router configurations directly**—automatically extracting and organizing IP addresses into their respective blocks, VLANs, and groups.  

---

## 📸 Screenshots
> *(Add your screenshots here)*  
- Dashboard view  
- Upload config page  
- IP block grouping  

---

## 🚀 Why EDEMROBIN?
Most open-source IPAM solutions are either:  
- Too heavy and complex with lots of tabs.  
- Require manual entry of IPs one by one.  
- Depend on APIs where you must convert configs into JSON before uploading.  

I wanted something simpler:  
✅ Upload router configs directly.  
✅ Automatically extract and organize IPs and VLANs.  
✅ Group them neatly under predefined IP blocks.  

When I couldn’t find a tool that did this, I built **EDEMROBIN**.  

---

## ⚡ Features
- 📂 **Upload router configs** (Cisco & MikroTik supported).  
- 🔍 **Automatic parsing**: Extracts IPs, VLANs, and NAT IPs.  
- 🗂️ **Organized grouping**: Groups IPs under predefined blocks.  
- 🚫 **Churned client detection**: Interfaces with `shutdown` are grouped automatically.  
- 👥 **Role-based access**: Manage users with different roles.  
- 🛠️ **REST API ready**: Access your configs programmatically via FastAPI endpoints.  
- 🗄️ **Flexible database**: Use SQLite for testing, or Postgres/MySQL for production.  

---

## 🌍 Use Cases
- Manage IPs across multiple routers with **one upload**.  
- Track churned/inactive client interfaces.  
- Use alongside existing IPAM tools to enhance automation workflows.  
- Ideal for **network engineers** needing a lightweight IPAM alternative.  

---

## 🛠️ Installation

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/edemrobin.git
cd edemrobin
```

### 2. Create a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate   # on Linux/Mac
venv\Scripts\activate      # on Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Database
By default, **SQLite** is used (stored as `edemrobin.db`).  

To use **PostgreSQL** or **MySQL**, update your `.env` file:

```env
# Example for PostgreSQL
DATABASE_URL=postgresql+psycopg2://user:password@localhost:5432/edemrobin

# Example for MySQL
DATABASE_URL=mysql+pymysql://user:password@localhost:3306/edemrobin
```

### 5. Run the app
```bash
uvicorn app.main:app --reload
```

The app will be available at **http://127.0.0.1:8000**

---

## 🛠️ Roadmap
- [ ] Add support for Juniper & Huawei configs  
- [ ] Export IP data (JSON/CSV/XLSX)  
- [ ] Integration with Ansible & NetBox  
- [ ] WebSocket-based live updates  

---

## 🤝 Contributing
Contributions are welcome! Please fork the repo and submit a pull request.  

---

## 📜 License
MIT License © 2025 [Your Name]  
