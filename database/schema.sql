CREATE TABLE IF NOT EXISTS device_logs (

    id SERIAL PRIMARY KEY,

    ip_address VARCHAR(50),
    mac_address VARCHAR(100),
    hostname TEXT,
    vendor TEXT,
    device_type TEXT,

    is_intruder BOOLEAN,

    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);