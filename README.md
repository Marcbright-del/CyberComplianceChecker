

# 🚀 ANTIC Cyber Compliance Checker (**AC³**)

**AC³** is a **full-stack web platform** designed to help organizations **assess, monitor, and maintain compliance** with national cybersecurity policies.
It combines **secure authentication**, **role-based access**, **automated scanning**, and **cryptographically signed PDF reports** to provide **trustworthy, verifiable compliance assessments**.

---

## ✨ Core Features

| Feature                                 | Description                                                                                                                      |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| 🔐 **Secure User Authentication**       | Multi-layered security with **JWT**, **MFA (TOTP)**, and **PKI-based client certificate authentication**.                        |
| 👥 **Role-Based Access Control (RBAC)** | **Admin**, **Auditor**, and **Client** roles with distinct permissions. Admins manage users/orgs, others have restricted access. |
| ⚙️ **Asynchronous Scanning**            | Uses **Celery + Redis** to run compliance scans in the background without blocking the UI.                                       |
| 🌐 **Real API Integration**             | Live checks with services like **IPQualityScore** for security & reputation scanning.                                            |
| 📊 **Detailed Compliance Audits**       | Configurable checklist scanning with a **weighted score** output.                                                                |
| 📝 **Verifiable PDF Reports**           | **Digitally signed** with a private key for authenticity.                                                                        |
| ✅ **Report Verification**               | Upload a report to verify its **integrity & authenticity** via cryptographic checks.                                             |
| 🗂 **User Management & Audit Trail**    | Admin UI for managing users + comprehensive **audit logs** of system actions.                                                    |
| 🧪 **Automated Testing**                | Backend tests (**pytest**) + frontend tests (**React Testing Library**) ensure quality.                                          |

---

## 🛠 Tech Stack

**Backend**

* 🐍 Django + **Django REST Framework**
* 🔑 **Simple JWT**, **Django-OTP**
* 🔒 `cryptography` for **digital signatures**
* 📨 Celery + Redis (Async tasks)
* 📄 **WeasyPrint** for PDFs
* 🗄 SQLite (dev) / PostgreSQL (prod)
* 🧪 Pytest, Pytest-Django

**Frontend**

* ⚛ React + **Vite**
* 🎨 Tailwind CSS
* 🔀 React Router
* 📦 React Context (State Management)
* 🧪 Vitest + React Testing Library

**Infrastructure**

* 🌐 **Nginx** (Reverse Proxy)
* ⚡ Daphne (ASGI Server)

---

## 🖥 Getting Started (Local Setup)

### 📋 Prerequisites

* **Python 3.10+**
* **Node.js & npm**
* **Redis**
* **Git**

---

### 🔹 Backend Setup (`AC3_Project`)

```bash
# Clone repository
git clone https://github.com/Marcbright-del/CyberComplianceChecker.git
cd CyberComplianceChecker

# Create & activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
cp .env.example .env
# Add SECRET_KEY and SCANNER_API_KEY in .env

# Run database migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Start backend server
python manage.py runserver
```

---

### 🔹 Frontend Setup (`ac3-vite-frontend`)

```bash
cd ../ac3-vite-frontend

# Install dependencies
npm install

# Start frontend server
npm run dev
```

➡ App available at: **[http://localhost:5173](http://localhost:5173)**

---

### 🔹 Running the Full Application

Open **3 terminals**:

```bash
# Terminal 1 - Django backend
python manage.py runserver

# Terminal 2 - Vite frontend
npm run dev

# Terminal 3 - Celery worker
celery -A ac3_backend worker -l info -P gevent
```

---

## 🧪 Running Tests

**Backend:**

```bash
pytest
```

**Frontend:**

```bash
npm test
```

---



---


