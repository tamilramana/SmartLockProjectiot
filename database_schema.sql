-- Users Table with security fields
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user', -- admin, user, viewer
    mfa_enabled INTEGER DEFAULT 0,
    mfa_secret TEXT,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Devices Table with API Keys and MAC whitelisting
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    device_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    location TEXT,
    status TEXT DEFAULT 'offline',
    api_key TEXT NOT NULL,
    mac_address TEXT UNIQUE,
    ip_address TEXT,
    last_heartbeat DATETIME,
    owner_id INTEGER,
    FOREIGN KEY(owner_id) REFERENCES users(id)
);

-- Secure Audit Logs with HMAC integrity
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    action TEXT NOT NULL,
    device_id TEXT,
    ip_address TEXT,
    details TEXT,
    severity TEXT DEFAULT 'info',
    log_hmac TEXT, -- Used to verify log integrity
    FOREIGN KEY(user_id) REFERENCES users(id)
);

-- Token Blacklist (Refresh Tokens)
CREATE TABLE IF NOT EXISTS token_blacklist (
    token TEXT PRIMARY KEY,
    expires_at DATETIME NOT NULL
);

-- Insert default admin (password: admin123! - Must be changed on first login)
-- Note: In a real app, you'd use the bcrypt script to generate this hash.
INSERT OR IGNORE INTO users (username, password_hash, role) 
VALUES ('admin', '$2b$12$6y9XfM/D.e1yK7y5v7v7v.G9y9XfM/D.e1yK7y5v7v7v.', 'admin');

-- Notifications Table
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    level TEXT NOT NULL,
    message TEXT NOT NULL
);

-- Schedules Table
CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    time TEXT,
    daysOfWeek TEXT,
    hour INTEGER,
    minute INTEGER,
    action TEXT NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);