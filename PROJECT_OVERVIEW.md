# Smart Lock Project - Simple Overview

## What is this project?
A **web-based smart lock control system** that allows users to manage and monitor smart door locks through a graphical interface. It's a full-stack application with a backend API and frontend web pages.

---

## Architecture (Simple Breakdown)

### Backend (Server Side)
- **Technology**: Node.js + Express.js
- **File**: `server.js`
- **Purpose**: Handles user authentication, device management, and data storage
- **Runs on**: `http://localhost:3000`

### Frontend (Client Side)
- **Technology**: HTML + Static Files
- **Main Pages**:
  - `login.html` - User login page
  - `index.html` - Dashboard (main page after login)
  - `devices.html` - View and control smart locks
  - `users.html` - Manage users
  - `schedules.html` - Create lock/unlock schedules
  - `notifications.html` - View system notifications
  - `logs.html` - View activity history

### Database
- **File**: `data.json`
- **Stores**: Users, devices, notifications, logs, and schedules

---

## Key Features

### 1. **Authentication**
- Users login with username/password
- System generates JWT (JSON Web Token) for secure sessions
- Default admin account: `admin / admin`

### 2. **Device Management**
- View all smart locks (e.g., "Front Door", "Garage")
- Lock/unlock devices remotely
- Track device status

### 3. **Scheduling**
- Create automatic lock/unlock schedules
- Examples: "Lock all doors at 9 PM", "Unlock front door at 7 AM"

### 4. **Notifications**
- System logs all activities
- Alerts for device changes
- Message severity levels: info, warning, critical

### 5. **User Management**
- Admin can add/remove users
- Different user roles (admin, user)

### 6. **Hardware Integration**
- `esp.ino` - Arduino code for the ESP32 smart lock device
- Communicates with the server via API

---

## How It Works (User Flow)

1. User opens `http://localhost:3000` → redirected to login page
2. User enters credentials → backend validates & creates session
3. User sees dashboard with all devices
4. User can:
   - Lock/unlock doors
   - View notifications
   - Create schedules
   - Manage users (if admin)
   - View activity logs

---

## Technical Stack

| Component | Technology |
|-----------|-----------|
| Server | Node.js, Express.js |
| Security | JWT, Helmet, CORS, Rate Limiting |
| Database | JSON file (data.json) |
| Frontend | HTML/CSS/JavaScript |
| Hardware | ESP32 (Arduino) |

---

## Installation & Running

```bash
# 1. Install dependencies
npm install

# 2. Start server
npm start

# 3. Open browser
Navigate to http://localhost:3000

# 4. Login
username: admin
password: admin
```

---

## Project Structure Summary

```
SmartLockProject/
├── server.js              ← Main backend API
├── data.json              ← Database (users, devices, etc.)
├── package.json           ← Dependencies & configuration
├── login.html             ← Login page
├── index.html             ← Dashboard
├── devices.html           ← Device control
├── users.html             ← User management
├── schedules.html         ← Schedule management
├── notifications.html     ← Activity notifications
├── logs.html              ← Activity logs
├── esp.ino                ← Arduino firmware for smart lock hardware
└── README.md              ← Quick start guide
```

---

## Security Features

✅ Password authentication  
✅ JWT-based sessions  
✅ CORS protection  
✅ Rate limiting (prevent abuse)  
✅ Helmet.js for security headers  
✅ HTTPS support (production-ready)

---

## Summary for Tutor

This is a **learning project** demonstrating:
- Full-stack web development (backend + frontend)
- User authentication & authorization
- API design with Express.js
- Data persistence (JSON)
- Real-time device management
- IoT integration (ESP32 hardware)

**Difficulty Level**: Intermediate - suitable for learning backend development, API design, and web application architecture.
