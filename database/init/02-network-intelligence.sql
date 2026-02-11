-- Network Intelligence Schema Extensions
-- Adds tables for AD Computers, DNS Reconciliation, DHCP Correlation,
-- Subnet Utilization Trends, Network Change Alerting, and IP Conflict Detection

-- =========================================
-- AD Computers Integration (3 tables)
-- =========================================

CREATE TABLE IF NOT EXISTS ad_computers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    computer_name VARCHAR(255) NOT NULL COMMENT 'AD computer CN',
    distinguished_name VARCHAR(1024) NOT NULL COMMENT 'Full AD DN',
    ou_path VARCHAR(1024) NULL COMMENT 'Parent OU distinguished name',
    dns_hostname VARCHAR(255) NULL COMMENT 'dNSHostName attribute',
    operating_system VARCHAR(255) NULL COMMENT 'operatingSystem attribute',
    os_version VARCHAR(255) NULL COMMENT 'operatingSystemVersion attribute',
    ip_address VARCHAR(45) NULL COMMENT 'Resolved IP address',
    mac_address VARCHAR(17) NULL COMMENT 'MAC address if discovered',
    description TEXT NULL COMMENT 'AD description attribute',
    is_enabled TINYINT(1) DEFAULT 1 COMMENT 'Derived from userAccountControl',
    last_logon DATETIME NULL COMMENT 'Converted from lastLogonTimestamp',
    when_created DATETIME NULL COMMENT 'AD whenCreated attribute',
    when_changed DATETIME NULL COMMENT 'AD whenChanged attribute',
    pwd_last_set DATETIME NULL COMMENT 'Converted from pwdLastSet',
    member_of TEXT NULL COMMENT 'Group memberships (JSON array)',
    ping_status ENUM('online','offline','unknown') DEFAULT 'unknown',
    ping_response_time DECIMAL(10,3) NULL COMMENT 'Last ping response time in ms',
    last_ping DATETIME NULL COMMENT 'Last ping attempt timestamp',
    phpipam_address_id INT NULL COMMENT 'Cross-reference to ipaddresses.id',
    phpipam_match_type ENUM('ip','hostname','mac','none') DEFAULT 'none' COMMENT 'How the match was found',
    is_stale TINYINT(1) DEFAULT 0 COMMENT 'Stale flag based on lastLogon threshold',
    stale_days INT NULL COMMENT 'Days since last logon',
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced DATETIME NULL COMMENT 'Last time synced from AD',
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_dn (distinguished_name(768)),
    INDEX idx_computer_name (computer_name),
    INDEX idx_ip (ip_address),
    INDEX idx_mac (mac_address),
    INDEX idx_ping_status (ping_status),
    INDEX idx_stale (is_stale),
    INDEX idx_phpipam_ref (phpipam_address_id),
    INDEX idx_ou (ou_path(768)),
    INDEX idx_last_synced (last_synced)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ad_sync_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sync_type ENUM('full','incremental','ou','single') DEFAULT 'full',
    ou_dn VARCHAR(1024) NULL COMMENT 'OU DN if sync_type is ou',
    status ENUM('pending','running','completed','failed') DEFAULT 'pending',
    computers_found INT DEFAULT 0,
    computers_added INT DEFAULT 0,
    computers_updated INT DEFAULT 0,
    computers_removed INT DEFAULT 0,
    stale_count INT DEFAULT 0,
    rogue_count INT DEFAULT 0,
    error_message TEXT NULL,
    started_at DATETIME NULL,
    completed_at DATETIME NULL,
    duration_seconds INT NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_created (created)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ad_ou_cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    distinguished_name VARCHAR(1024) NOT NULL,
    name VARCHAR(255) NOT NULL COMMENT 'OU display name',
    parent_dn VARCHAR(1024) NULL COMMENT 'Parent OU DN',
    depth INT DEFAULT 0 COMMENT 'Depth in OU tree',
    computer_count INT DEFAULT 0 COMMENT 'Number of computers in this OU',
    last_synced DATETIME NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_dn (distinguished_name(768)),
    INDEX idx_parent (parent_dn(768)),
    INDEX idx_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =========================================
-- DNS Reconciliation (2 tables)
-- =========================================

CREATE TABLE IF NOT EXISTS dns_checks (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    batch_id INT NULL COMMENT 'Reference to dns_check_batches',
    subnet_id INT NULL COMMENT 'Reference to subnets table',
    ip_address VARCHAR(45) NOT NULL,
    phpipam_hostname VARCHAR(255) NULL COMMENT 'Hostname stored in PHPIPAM',
    forward_result VARCHAR(255) NULL COMMENT 'IP from forward DNS lookup',
    reverse_result VARCHAR(255) NULL COMMENT 'Hostname from reverse DNS lookup',
    mismatch_type ENUM(
        'none','no_ptr','no_a_record','forward_mismatch',
        'reverse_mismatch','both_mismatch','no_phpipam_hostname','orphan_dns'
    ) DEFAULT 'none',
    dns_server VARCHAR(255) NULL COMMENT 'DNS server used for check',
    response_time_ms DECIMAL(10,3) NULL,
    checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_batch (batch_id),
    INDEX idx_subnet (subnet_id),
    INDEX idx_ip (ip_address),
    INDEX idx_mismatch (mismatch_type),
    INDEX idx_checked (checked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS dns_check_batches (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scope ENUM('all','subnet','single') DEFAULT 'all',
    subnet_id INT NULL COMMENT 'If scope=subnet',
    status ENUM('pending','running','completed','failed') DEFAULT 'pending',
    total_checks INT DEFAULT 0,
    mismatches_found INT DEFAULT 0,
    dns_server VARCHAR(255) NULL,
    error_message TEXT NULL,
    started_at DATETIME NULL,
    completed_at DATETIME NULL,
    duration_seconds INT NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_created (created)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =========================================
-- DHCP Lease Correlation (3 tables)
-- =========================================

CREATE TABLE IF NOT EXISTS dhcp_servers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL COMMENT 'Display name',
    server_type ENUM('isc-dhcpd','kea','windows','infoblox') NOT NULL,
    access_method ENUM('file','api','database','ssh') NOT NULL,
    -- File-based access
    lease_file_path VARCHAR(512) NULL COMMENT 'Path to lease file (mounted volume)',
    -- API-based access
    api_url VARCHAR(512) NULL,
    api_key VARCHAR(512) NULL,
    -- Database-based access
    db_host VARCHAR(255) NULL,
    db_port INT NULL,
    db_user VARCHAR(255) NULL,
    db_password VARCHAR(512) NULL,
    db_name VARCHAR(255) NULL,
    -- General
    enabled TINYINT(1) DEFAULT 1,
    last_sync DATETIME NULL,
    last_sync_status ENUM('success','failed') NULL,
    lease_count INT DEFAULT 0 COMMENT 'Last known lease count',
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS dhcp_leases (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    server_id INT NOT NULL COMMENT 'Reference to dhcp_servers',
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(17) NULL,
    hostname VARCHAR(255) NULL COMMENT 'Client hostname from DHCP',
    lease_start DATETIME NULL,
    lease_end DATETIME NULL,
    lease_state ENUM('active','expired','released','backup') DEFAULT 'active',
    subnet_mask VARCHAR(45) NULL,
    router VARCHAR(45) NULL COMMENT 'Default gateway from DHCP',
    dns_servers VARCHAR(512) NULL,
    -- Correlation fields
    correlation_status ENUM(
        'matched','lease_only','ipam_only','mac_mismatch','hostname_mismatch'
    ) DEFAULT 'lease_only',
    phpipam_address_id INT NULL COMMENT 'Cross-reference to ipaddresses.id',
    phpipam_hostname VARCHAR(255) NULL COMMENT 'Hostname in PHPIPAM for comparison',
    phpipam_mac VARCHAR(17) NULL COMMENT 'MAC in PHPIPAM for comparison',
    last_synced DATETIME NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_server (server_id),
    INDEX idx_ip (ip_address),
    INDEX idx_mac (mac_address),
    INDEX idx_state (lease_state),
    INDEX idx_correlation (correlation_status),
    INDEX idx_phpipam_ref (phpipam_address_id),
    INDEX idx_lease_end (lease_end)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS dhcp_sync_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_id INT NOT NULL COMMENT 'Reference to dhcp_servers',
    status ENUM('pending','running','completed','failed') DEFAULT 'pending',
    leases_found INT DEFAULT 0,
    leases_matched INT DEFAULT 0,
    leases_unmatched INT DEFAULT 0,
    mac_mismatches INT DEFAULT 0,
    hostname_mismatches INT DEFAULT 0,
    error_message TEXT NULL,
    started_at DATETIME NULL,
    completed_at DATETIME NULL,
    duration_seconds INT NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_server (server_id),
    INDEX idx_status (status),
    INDEX idx_created (created)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =========================================
-- Subnet Utilization Trends (2 tables)
-- =========================================

CREATE TABLE IF NOT EXISTS subnet_utilization_snapshots (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    subnet_id INT NOT NULL COMMENT 'Reference to subnets table',
    scan_id INT NULL COMMENT 'Reference to subnet_scans if triggered by scan',
    total_hosts INT NOT NULL DEFAULT 0 COMMENT 'Total usable host addresses',
    used_hosts INT NOT NULL DEFAULT 0 COMMENT 'Addresses assigned in PHPIPAM',
    active_hosts INT NOT NULL DEFAULT 0 COMMENT 'Hosts responding to ping',
    reserved_hosts INT NOT NULL DEFAULT 0 COMMENT 'Addresses marked reserved (state=3)',
    dhcp_hosts INT NOT NULL DEFAULT 0 COMMENT 'Addresses marked DHCP (state=4)',
    free_hosts INT NOT NULL DEFAULT 0 COMMENT 'Unassigned host addresses',
    utilization_percent DECIMAL(5,2) DEFAULT 0.00 COMMENT 'used_hosts/total_hosts * 100',
    active_percent DECIMAL(5,2) DEFAULT 0.00 COMMENT 'active_hosts/total_hosts * 100',
    snapshot_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_subnet (subnet_id),
    INDEX idx_time (snapshot_time),
    INDEX idx_subnet_time (subnet_id, snapshot_time),
    INDEX idx_utilization (utilization_percent)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS subnet_utilization_daily (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    subnet_id INT NOT NULL COMMENT 'Reference to subnets table',
    date DATE NOT NULL COMMENT 'Aggregation date',
    avg_utilization DECIMAL(5,2) DEFAULT 0.00,
    max_utilization DECIMAL(5,2) DEFAULT 0.00,
    min_utilization DECIMAL(5,2) DEFAULT 0.00,
    avg_active DECIMAL(5,2) DEFAULT 0.00,
    max_active DECIMAL(5,2) DEFAULT 0.00,
    snapshot_count INT DEFAULT 0 COMMENT 'Number of snapshots aggregated',
    total_hosts INT DEFAULT 0 COMMENT 'Total hosts (from last snapshot)',
    used_hosts_avg INT DEFAULT 0,
    free_hosts_avg INT DEFAULT 0,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_subnet_date (subnet_id, date),
    INDEX idx_date (date),
    INDEX idx_utilization (avg_utilization)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =========================================
-- Network Change Alerting (3 tables)
-- =========================================

CREATE TABLE IF NOT EXISTS network_alerts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    alert_type ENUM(
        'new_device','new_mac','device_moved','host_offline','host_online',
        'ip_conflict','dns_mismatch','dhcp_mismatch','rogue_device',
        'stale_computer','subnet_threshold'
    ) NOT NULL,
    severity ENUM('info','warning','critical') DEFAULT 'info',
    subnet_id INT NULL,
    ip_address VARCHAR(45) NULL,
    mac_address VARCHAR(17) NULL,
    hostname VARCHAR(255) NULL,
    title VARCHAR(512) NOT NULL COMMENT 'Alert summary',
    details TEXT NULL COMMENT 'JSON with full alert context',
    source_type VARCHAR(50) NULL COMMENT 'Which collector generated this',
    source_id BIGINT NULL COMMENT 'Reference to source record',
    is_acknowledged TINYINT(1) DEFAULT 0,
    acknowledged_by INT NULL COMMENT 'User ID who acknowledged',
    acknowledged_at DATETIME NULL,
    is_resolved TINYINT(1) DEFAULT 0,
    resolved_by INT NULL,
    resolved_at DATETIME NULL,
    resolution_notes TEXT NULL,
    is_false_positive TINYINT(1) DEFAULT 0,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_type (alert_type),
    INDEX idx_severity (severity),
    INDEX idx_subnet (subnet_id),
    INDEX idx_ip (ip_address),
    INDEX idx_acknowledged (is_acknowledged),
    INDEX idx_resolved (is_resolved),
    INDEX idx_created (created),
    INDEX idx_type_severity (alert_type, severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS alert_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type ENUM(
        'new_device','new_mac','device_moved','host_offline','host_online',
        'ip_conflict','dns_mismatch','dhcp_mismatch','rogue_device',
        'stale_computer','subnet_threshold'
    ) NOT NULL,
    enabled TINYINT(1) DEFAULT 1,
    severity ENUM('info','warning','critical') DEFAULT 'info',
    notification_method ENUM('db_only','email','webhook','email_and_webhook') DEFAULT 'db_only',
    email_recipients VARCHAR(1024) NULL COMMENT 'Comma-separated email addresses',
    webhook_url VARCHAR(512) NULL,
    cooldown_minutes INT DEFAULT 60 COMMENT 'Minutes between repeat alerts for same source',
    threshold_value DECIMAL(10,2) NULL COMMENT 'For threshold-based alerts (e.g., utilization %)',
    description TEXT NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_alert_type (alert_type),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default alert rules
INSERT INTO alert_rules (alert_type, enabled, severity, notification_method, cooldown_minutes, description) VALUES
    ('new_device', 1, 'info', 'db_only', 60, 'New device discovered on network'),
    ('new_mac', 1, 'info', 'db_only', 60, 'New MAC address seen on network'),
    ('device_moved', 1, 'warning', 'db_only', 120, 'Device moved to different subnet'),
    ('host_offline', 1, 'warning', 'db_only', 240, 'Previously online host went offline'),
    ('host_online', 1, 'info', 'db_only', 60, 'Previously offline host came online'),
    ('ip_conflict', 1, 'critical', 'db_only', 30, 'IP address conflict detected (multiple MACs)'),
    ('dns_mismatch', 1, 'warning', 'db_only', 360, 'DNS forward/reverse mismatch detected'),
    ('dhcp_mismatch', 1, 'warning', 'db_only', 360, 'DHCP lease does not match PHPIPAM allocation'),
    ('rogue_device', 1, 'critical', 'db_only', 60, 'Network device not found in Active Directory'),
    ('stale_computer', 1, 'info', 'db_only', 1440, 'AD computer object has not logged on recently'),
    ('subnet_threshold', 1, 'warning', 'db_only', 720, 'Subnet utilization exceeded threshold')
ON DUPLICATE KEY UPDATE updated = CURRENT_TIMESTAMP;

CREATE TABLE IF NOT EXISTS network_state_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    subnet_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(17) NULL,
    hostname VARCHAR(255) NULL,
    is_alive TINYINT(1) DEFAULT 0,
    scan_id INT NULL COMMENT 'Reference to subnet_scans',
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_subnet (subnet_id),
    INDEX idx_ip (ip_address),
    INDEX idx_mac (mac_address),
    INDEX idx_recorded (recorded_at),
    INDEX idx_subnet_ip (subnet_id, ip_address),
    INDEX idx_subnet_recorded (subnet_id, recorded_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =========================================
-- IP Conflict Detection (1 table)
-- =========================================

CREATE TABLE IF NOT EXISTS ip_conflicts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    subnet_id INT NULL COMMENT 'Reference to subnets table',
    ip_address VARCHAR(45) NOT NULL,
    mac_1 VARCHAR(17) NOT NULL COMMENT 'First MAC claiming this IP',
    mac_1_vendor VARCHAR(100) NULL COMMENT 'OUI vendor for MAC 1',
    mac_1_hostname VARCHAR(255) NULL,
    mac_2 VARCHAR(17) NOT NULL COMMENT 'Second MAC claiming this IP',
    mac_2_vendor VARCHAR(100) NULL COMMENT 'OUI vendor for MAC 2',
    mac_2_hostname VARCHAR(255) NULL,
    detection_method ENUM('arp_scan','gratuitous_arp','scan_comparison') DEFAULT 'arp_scan',
    status ENUM('active','resolved','false_positive') DEFAULT 'active',
    first_detected DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_detected DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME NULL,
    resolved_by INT NULL,
    resolution_notes TEXT NULL,
    alert_id BIGINT NULL COMMENT 'Reference to network_alerts',
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address),
    INDEX idx_status (status),
    INDEX idx_subnet (subnet_id),
    INDEX idx_mac1 (mac_1),
    INDEX idx_mac2 (mac_2),
    INDEX idx_first_detected (first_detected),
    INDEX idx_alert (alert_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
