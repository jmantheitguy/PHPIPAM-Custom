-- IPAM Schema Extensions
-- These tables extend PHPIPAM's base schema with additional functionality

-- Active Directory Configuration
CREATE TABLE IF NOT EXISTS ad_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server VARCHAR(255) NOT NULL COMMENT 'LDAP server URL',
    base_dn VARCHAR(255) NOT NULL COMMENT 'Base DN for searches',
    bind_user VARCHAR(255) NOT NULL COMMENT 'Bind username',
    bind_password VARCHAR(512) NOT NULL COMMENT 'Encrypted bind password',
    group_field VARCHAR(255) DEFAULT 'memberOf' COMMENT 'LDAP field for group membership',
    user_filter VARCHAR(512) DEFAULT '(objectClass=user)' COMMENT 'LDAP user filter',
    admin_group VARCHAR(255) DEFAULT NULL COMMENT 'AD group for admin access',
    user_group VARCHAR(255) DEFAULT NULL COMMENT 'AD group for user access',
    use_tls TINYINT(1) DEFAULT 1 COMMENT 'Use TLS for LDAP connection',
    active TINYINT(1) DEFAULT 1 COMMENT 'Configuration active flag',
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Subnet Scan Operations
CREATE TABLE IF NOT EXISTS subnet_scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    subnet_id INT NOT NULL COMMENT 'Reference to subnets table',
    start_time TIMESTAMP NULL COMMENT 'Scan start time',
    end_time TIMESTAMP NULL COMMENT 'Scan end time',
    total_hosts INT NOT NULL DEFAULT 0 COMMENT 'Total hosts in subnet',
    active_hosts INT NOT NULL DEFAULT 0 COMMENT 'Number of active hosts found',
    status ENUM('pending','running','completed','failed','cancelled') DEFAULT 'pending',
    scan_type ENUM('ping','arp','ndp','nmap') DEFAULT 'ping' COMMENT 'Type of scan performed',
    results JSON NULL COMMENT 'JSON results of scan',
    error_message TEXT NULL COMMENT 'Error message if failed',
    created_by INT NOT NULL COMMENT 'User who initiated scan',
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_subnet (subnet_id),
    INDEX idx_status (status),
    INDEX idx_created (created)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Host Discovery Results
CREATE TABLE IF NOT EXISTS host_discovery (
    id INT AUTO_INCREMENT PRIMARY KEY,
    subnet_id INT NOT NULL COMMENT 'Reference to subnets table',
    ip_address VARCHAR(45) NOT NULL COMMENT 'Discovered IP address',
    mac_address VARCHAR(17) NULL COMMENT 'MAC address if discovered',
    hostname VARCHAR(255) NULL COMMENT 'Hostname from reverse DNS',
    status ENUM('active','inactive','unknown') DEFAULT 'unknown',
    device_type VARCHAR(50) NULL COMMENT 'Device type if identified',
    os_family VARCHAR(50) NULL COMMENT 'OS family if identified',
    vendor VARCHAR(100) NULL COMMENT 'Vendor from MAC OUI lookup',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NULL,
    notes TEXT NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_subnet_ip (subnet_id, ip_address),
    INDEX idx_mac (mac_address),
    INDEX idx_status (status),
    INDEX idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Ping Operations
CREATE TABLE IF NOT EXISTS ping_operations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL COMMENT 'Target IP address',
    subnet_id INT NULL COMMENT 'Optional reference to subnets table',
    status ENUM('pending','running','completed','failed') DEFAULT 'pending',
    response_time DECIMAL(10,3) NULL COMMENT 'Response time in milliseconds',
    success TINYINT(1) NULL COMMENT 'Ping success flag',
    packet_loss DECIMAL(5,2) NULL COMMENT 'Packet loss percentage',
    results JSON NULL COMMENT 'Detailed ping results',
    created_by INT NULL COMMENT 'User who initiated ping',
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address),
    INDEX idx_status (status),
    INDEX idx_created (created)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Batch Ping Operations
CREATE TABLE IF NOT EXISTS ping_batches (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NULL COMMENT 'Batch operation name',
    ip_range VARCHAR(255) NOT NULL COMMENT 'IP range or list',
    total_ips INT NOT NULL DEFAULT 0,
    completed_ips INT NOT NULL DEFAULT 0,
    successful_ips INT NOT NULL DEFAULT 0,
    status ENUM('pending','running','completed','failed','cancelled') DEFAULT 'pending',
    results JSON NULL,
    created_by INT NULL,
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_created_by (created_by)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Scanner Agent Configuration
CREATE TABLE IF NOT EXISTS scanner_agents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL COMMENT 'Agent name',
    description TEXT NULL,
    type ENUM('local','remote') DEFAULT 'local',
    endpoint VARCHAR(255) NULL COMMENT 'Remote agent endpoint',
    api_key VARCHAR(64) NULL COMMENT 'API key for remote agents',
    last_seen TIMESTAMP NULL,
    status ENUM('online','offline','error') DEFAULT 'offline',
    capabilities JSON NULL COMMENT 'Agent capabilities',
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default local scanner agent
INSERT INTO scanner_agents (name, description, type, status, capabilities)
VALUES ('local-scanner', 'Default local scanner agent', 'local', 'online',
        '{"ping": true, "arp": true, "nmap": true}')
ON DUPLICATE KEY UPDATE updated = CURRENT_TIMESTAMP;

-- Audit Log for IPAM operations
CREATE TABLE IF NOT EXISTS ipam_audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    username VARCHAR(100) NULL,
    action VARCHAR(50) NOT NULL COMMENT 'Action performed',
    object_type VARCHAR(50) NOT NULL COMMENT 'Type of object affected',
    object_id INT NULL COMMENT 'ID of affected object',
    old_values JSON NULL COMMENT 'Previous values',
    new_values JSON NULL COMMENT 'New values',
    ip_address VARCHAR(45) NULL COMMENT 'Client IP address',
    user_agent VARCHAR(255) NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_id),
    INDEX idx_action (action),
    INDEX idx_object (object_type, object_id),
    INDEX idx_created (created)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
