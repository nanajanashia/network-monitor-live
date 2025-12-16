CREATE DATABASE network_monitor;

\c network_monitor

CREATE TABLE IF NOT EXISTS packet_info (
    id SERIAL PRIMARY KEY,
    version VARCHAR(10),
    total_length INTEGER,
    flags VARCHAR(20),
    ttl INTEGER,
    protocol VARCHAR(20),
    header_checksum INTEGER,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    malicious INTEGER,
    suspicious INTEGER,
    harmless INTEGER,
    undetected INTEGER,
    scan_date DATE,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
