#!/usr/bin/env python3
"""
IPAM Subnet Scanner Service

Provides network scanning capabilities including:
- ICMP ping scanning
- ARP discovery
- NDP (IPv6 neighbor discovery)
- DNS reverse lookups
- AD computer sync
- DNS reconciliation
- DHCP lease correlation
- Subnet utilization tracking
- Network change detection
- IP conflict detection
"""

import os
import sys
import json
import socket
import logging
import subprocess
import ipaddress
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import mysql.connector
import redis
import schedule

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('subnet-scanner')

# Configuration from environment
MYSQL_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'mysql'),
    'user': os.getenv('MYSQL_USER', 'phpipam'),
    'password': os.getenv('MYSQL_PASSWORD', ''),
    'database': os.getenv('MYSQL_DATABASE', 'phpipam'),
}

REDIS_CONFIG = {
    'host': os.getenv('REDIS_HOST', 'redis'),
    'port': int(os.getenv('REDIS_PORT', 6379)),
    'decode_responses': True,
}

SCAN_INTERVAL = int(os.getenv('SCAN_INTERVAL', 300))
SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', 2))
SCAN_CONCURRENT = int(os.getenv('SCAN_CONCURRENT', 50))

# Feature flags for features that require external config
AD_ENABLED = os.getenv('AD_ENABLED', 'false').lower() == 'true'
DHCP_ENABLED = os.getenv('DHCP_ENABLED', 'false').lower() == 'true'

# Network Intelligence intervals
AD_SYNC_INTERVAL = int(os.getenv('AD_SYNC_INTERVAL', 14400))
DNS_CHECK_INTERVAL = int(os.getenv('DNS_CHECK_INTERVAL', 3600))
DHCP_SYNC_INTERVAL = int(os.getenv('DHCP_SYNC_INTERVAL', 600))

# Import collectors
from collectors.ad_collector import ADCollector
from collectors.dns_collector import DNSReconciler
from collectors.dhcp_collector import DHCPCollector
from collectors.utilization_collector import UtilizationCollector
from collectors.change_detector import ChangeDetector
from collectors.conflict_detector import ConflictDetector


class DatabaseConnection:
    """MySQL database connection manager."""

    def __init__(self, config):
        self.config = config
        self.conn = None

    def __enter__(self):
        self.conn = mysql.connector.connect(**self.config)
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.close()


class RedisConnection:
    """Redis connection manager."""

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = redis.Redis(**REDIS_CONFIG)
        return cls._instance


# Initialize collectors
ad_collector = ADCollector(DatabaseConnection, ping_host=None, mysql_config=MYSQL_CONFIG)
dns_reconciler = DNSReconciler(DatabaseConnection, MYSQL_CONFIG)
dhcp_collector = DHCPCollector(DatabaseConnection, MYSQL_CONFIG)
utilization_collector = UtilizationCollector(DatabaseConnection, MYSQL_CONFIG)
change_detector = ChangeDetector(DatabaseConnection, MYSQL_CONFIG)
conflict_detector = ConflictDetector(DatabaseConnection, MYSQL_CONFIG)


def ping_host(ip_address: str, timeout: int = SCAN_TIMEOUT) -> dict:
    """
    Ping a single host and return results.

    Args:
        ip_address: IP address to ping
        timeout: Ping timeout in seconds

    Returns:
        Dictionary with ping results
    """
    result = {
        'ip': ip_address,
        'alive': False,
        'response_time': None,
        'mac_address': None,
        'hostname': None,
        'timestamp': datetime.utcnow().isoformat(),
    }

    try:
        # Execute ping command
        cmd = ['ping', '-c', '1', '-W', str(timeout), ip_address]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)

        if proc.returncode == 0:
            result['alive'] = True
            # Parse response time from output
            for line in proc.stdout.split('\n'):
                if 'time=' in line:
                    try:
                        time_str = line.split('time=')[1].split()[0]
                        result['response_time'] = float(time_str.replace('ms', ''))
                    except (IndexError, ValueError):
                        pass
                    break

            # Try to get MAC address from ARP cache
            try:
                arp_cmd = ['arp', '-n', ip_address]
                arp_proc = subprocess.run(arp_cmd, capture_output=True, text=True, timeout=5)
                if arp_proc.returncode == 0:
                    for line in arp_proc.stdout.split('\n'):
                        if ip_address in line:
                            parts = line.split()
                            for part in parts:
                                if ':' in part and len(part) == 17:
                                    result['mac_address'] = part.upper()
                                    break
            except Exception:
                pass

            # Try reverse DNS lookup
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_address)
                result['hostname'] = hostname
            except socket.herror:
                pass

    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        logger.debug(f"Error pinging {ip_address}: {e}")

    return result


# Set ping_host reference on AD collector after function is defined
ad_collector.ping_host = ping_host


def scan_subnet(subnet_cidr: str, scan_id: int = None) -> list:
    """
    Scan an entire subnet using parallel ping.

    Args:
        subnet_cidr: Subnet in CIDR notation (e.g., '192.168.1.0/24')
        scan_id: Optional scan operation ID for tracking

    Returns:
        List of scan results
    """
    logger.info(f"Starting scan of subnet: {subnet_cidr}")

    try:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
    except ValueError as e:
        logger.error(f"Invalid subnet CIDR: {subnet_cidr} - {e}")
        return []

    # Get list of host IPs (excluding network and broadcast for IPv4)
    if network.version == 4:
        hosts = list(network.hosts())
    else:
        # For IPv6, limit to first 256 addresses for practical scanning
        hosts = list(network.hosts())[:256]

    total_hosts = len(hosts)
    logger.info(f"Scanning {total_hosts} hosts in {subnet_cidr}")

    results = []
    active_count = 0

    # Update scan status in database
    if scan_id:
        update_scan_status(scan_id, 'running', total_hosts)

    # Parallel scanning with ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=SCAN_CONCURRENT) as executor:
        future_to_ip = {
            executor.submit(ping_host, str(ip)): str(ip)
            for ip in hosts
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                results.append(result)
                if result['alive']:
                    active_count += 1
                    logger.debug(f"Host alive: {ip} ({result['response_time']}ms)")
            except Exception as e:
                logger.error(f"Error scanning {ip}: {e}")

    logger.info(f"Scan complete: {active_count}/{total_hosts} hosts active")

    # Update scan status
    if scan_id:
        update_scan_status(scan_id, 'completed', total_hosts, active_count, results)

    return results


def update_scan_status(scan_id: int, status: str, total_hosts: int = 0,
                       active_hosts: int = 0, results: list = None):
    """Update scan operation status in database."""
    try:
        with DatabaseConnection(MYSQL_CONFIG) as conn:
            cursor = conn.cursor()

            if status == 'running':
                cursor.execute("""
                    UPDATE subnet_scans
                    SET status = %s, start_time = NOW(), total_hosts = %s
                    WHERE id = %s
                """, (status, total_hosts, scan_id))
            elif status == 'completed':
                cursor.execute("""
                    UPDATE subnet_scans
                    SET status = %s, end_time = NOW(), active_hosts = %s,
                        results = %s
                    WHERE id = %s
                """, (status, active_hosts, json.dumps(results), scan_id))
            else:
                cursor.execute("""
                    UPDATE subnet_scans SET status = %s WHERE id = %s
                """, (status, scan_id))

            conn.commit()
            logger.debug(f"Updated scan {scan_id} status to {status}")
    except Exception as e:
        logger.error(f"Failed to update scan status: {e}")


def save_discovery_results(subnet_id: int, results: list):
    """Save discovered hosts to database."""
    try:
        with DatabaseConnection(MYSQL_CONFIG) as conn:
            cursor = conn.cursor()

            for result in results:
                if result['alive']:
                    cursor.execute("""
                        INSERT INTO host_discovery
                        (subnet_id, ip_address, mac_address, status, last_seen)
                        VALUES (%s, %s, %s, 'active', NOW())
                        ON DUPLICATE KEY UPDATE
                        mac_address = COALESCE(VALUES(mac_address), mac_address),
                        status = 'active',
                        last_seen = NOW()
                    """, (subnet_id, result['ip'], result['mac_address']))

            conn.commit()
            logger.info(f"Saved {len([r for r in results if r['alive']])} discovered hosts")
    except Exception as e:
        logger.error(f"Failed to save discovery results: {e}")


def process_scan_queue():
    """Process pending scan requests from Redis queue."""
    redis_client = RedisConnection.get_instance()

    try:
        # Check for pending scans in queue
        scan_data = redis_client.lpop('ipam:scan_queue')

        if scan_data:
            scan_request = json.loads(scan_data)
            logger.info(f"Processing scan request: {scan_request}")

            subnet_cidr = scan_request.get('subnet')
            scan_id = scan_request.get('scan_id')
            subnet_id = scan_request.get('subnet_id')

            if subnet_cidr:
                results = scan_subnet(subnet_cidr, scan_id)

                if subnet_id:
                    save_discovery_results(subnet_id, results)

                    # Network Intelligence: post-scan processing
                    try:
                        change_detector.save_current_state(
                            subnet_id, results, scan_id)
                        change_detector.compare_scan_results(
                            subnet_id, results)
                        conflict_detector.process_scan_results(
                            subnet_id, subnet_cidr, results)
                        utilization_collector.capture_snapshot(
                            subnet_id, scan_id)
                    except Exception as e:
                        logger.error(f"Post-scan processing error: {e}")

                # Publish results
                redis_client.publish('ipam:scan_results', json.dumps({
                    'scan_id': scan_id,
                    'subnet': subnet_cidr,
                    'results': results,
                    'timestamp': datetime.utcnow().isoformat(),
                }))
    except Exception as e:
        logger.error(f"Error processing scan queue: {e}")


def process_ping_queue():
    """Process pending ping requests from Redis queue."""
    redis_client = RedisConnection.get_instance()

    try:
        ping_data = redis_client.lpop('ipam:ping_queue')

        if ping_data:
            ping_request = json.loads(ping_data)
            logger.info(f"Processing ping request: {ping_request}")

            ip_address = ping_request.get('ip')
            operation_id = ping_request.get('operation_id')

            if ip_address:
                result = ping_host(ip_address)

                # Update ping operation in database
                if operation_id:
                    try:
                        with DatabaseConnection(MYSQL_CONFIG) as conn:
                            cursor = conn.cursor()
                            cursor.execute("""
                                UPDATE ping_operations
                                SET status = 'completed',
                                    success = %s,
                                    response_time = %s,
                                    results = %s
                                WHERE id = %s
                            """, (
                                result['alive'],
                                result['response_time'],
                                json.dumps(result),
                                operation_id
                            ))
                            conn.commit()
                    except Exception as e:
                        logger.error(f"Failed to update ping operation: {e}")

                # Publish result
                redis_client.publish('ipam:ping_results', json.dumps({
                    'operation_id': operation_id,
                    'result': result,
                }))
    except Exception as e:
        logger.error(f"Error processing ping queue: {e}")


def process_ad_sync_queue():
    """Process AD sync requests from Redis queue."""
    if not AD_ENABLED:
        return
    redis_client = RedisConnection.get_instance()
    try:
        data = redis_client.lpop('ipam:ad_sync_queue')
        if data:
            request = json.loads(data)
            logger.info(f"Processing AD sync request: {request}")
            ou_dn = request.get('ou_dn')
            sync_id = ad_collector.sync_computers(ou_dn)
            redis_client.publish('ipam:ad_sync_results', json.dumps({
                'sync_id': sync_id,
                'timestamp': datetime.utcnow().isoformat(),
            }))
    except Exception as e:
        logger.error(f"Error processing AD sync queue: {e}")


def process_dns_check_queue():
    """Process DNS reconciliation requests from Redis queue."""
    redis_client = RedisConnection.get_instance()
    try:
        data = redis_client.lpop('ipam:dns_check_queue')
        if data:
            request = json.loads(data)
            logger.info(f"Processing DNS check request: {request}")
            scope = request.get('scope', 'all')
            subnet_id = request.get('subnet_id')

            if scope == 'all':
                batch_id = dns_reconciler.reconcile_all()
            elif scope == 'subnet' and subnet_id:
                batch_id = dns_reconciler._create_batch('subnet', subnet_id)
                dns_reconciler._update_batch_status(batch_id, 'running')
                results = dns_reconciler.reconcile_subnet(subnet_id, batch_id)
                mismatches = sum(1 for r in results
                                 if r['mismatch_type'] != 'none')
                dns_reconciler._update_batch_status(
                    batch_id, 'completed',
                    total_checks=len(results),
                    mismatches=mismatches)
            else:
                batch_id = None

            redis_client.publish('ipam:dns_check_results', json.dumps({
                'batch_id': batch_id,
                'timestamp': datetime.utcnow().isoformat(),
            }))
    except Exception as e:
        logger.error(f"Error processing DNS check queue: {e}")


def process_dhcp_sync_queue():
    """Process DHCP sync requests from Redis queue."""
    if not DHCP_ENABLED:
        return
    redis_client = RedisConnection.get_instance()
    try:
        data = redis_client.lpop('ipam:dhcp_sync_queue')
        if data:
            request = json.loads(data)
            logger.info(f"Processing DHCP sync request: {request}")
            server_id = request.get('server_id')
            if server_id:
                sync_id = dhcp_collector.sync_leases(server_id)
                redis_client.publish('ipam:dhcp_sync_results', json.dumps({
                    'sync_id': sync_id,
                    'server_id': server_id,
                    'timestamp': datetime.utcnow().isoformat(),
                }))
    except Exception as e:
        logger.error(f"Error processing DHCP sync queue: {e}")


def process_conflict_queue():
    """Process IP conflict scan requests from Redis queue."""
    redis_client = RedisConnection.get_instance()
    try:
        data = redis_client.lpop('ipam:conflict_queue')
        if data:
            request = json.loads(data)
            logger.info(f"Processing conflict scan request: {request}")
            subnet_cidr = request.get('subnet_cidr')
            subnet_id = request.get('subnet_id')
            if subnet_cidr:
                conflicts = conflict_detector.scan_for_conflicts(subnet_cidr)
                for c in conflicts:
                    conflict_detector.store_conflict(c, subnet_id)
                redis_client.publish('ipam:conflict_results', json.dumps({
                    'subnet_cidr': subnet_cidr,
                    'conflicts_found': len(conflicts),
                    'timestamp': datetime.utcnow().isoformat(),
                }))
    except Exception as e:
        logger.error(f"Error processing conflict queue: {e}")


def scheduled_subnet_scan():
    """Run scheduled subnet scans based on database configuration."""
    logger.info("Running scheduled subnet scan check")

    try:
        with DatabaseConnection(MYSQL_CONFIG) as conn:
            cursor = conn.cursor(dictionary=True)

            # Get subnets with scanning enabled
            cursor.execute("""
                SELECT id, subnet, mask
                FROM subnets
                WHERE scanAgent = 1
                AND isFolder = 0
            """)

            subnets = cursor.fetchall()

            for subnet in subnets:
                try:
                    # Calculate CIDR notation
                    cidr = f"{subnet['subnet']}/{subnet['mask']}"

                    # Create scan record
                    cursor.execute("""
                        INSERT INTO subnet_scans
                        (subnet_id, status, scan_type, created_by)
                        VALUES (%s, 'pending', 'ping', 1)
                    """, (subnet['id'],))
                    conn.commit()
                    scan_id = cursor.lastrowid

                    # Queue the scan
                    redis_client = RedisConnection.get_instance()
                    redis_client.rpush('ipam:scan_queue', json.dumps({
                        'subnet': cidr,
                        'scan_id': scan_id,
                        'subnet_id': subnet['id'],
                    }))

                    logger.info(f"Queued scheduled scan for {cidr}")
                except Exception as e:
                    logger.error(f"Error scheduling scan for subnet {subnet['id']}: {e}")

    except Exception as e:
        logger.error(f"Error running scheduled scan: {e}")


def scheduled_ad_sync():
    """Scheduled AD computer sync."""
    if not AD_ENABLED:
        return
    logger.info("Running scheduled AD sync")
    try:
        ad_collector.sync_computers()
    except Exception as e:
        logger.error(f"Scheduled AD sync failed: {e}")


def scheduled_dns_check():
    """Scheduled DNS reconciliation."""
    logger.info("Running scheduled DNS check")
    try:
        dns_reconciler.reconcile_all()
    except Exception as e:
        logger.error(f"Scheduled DNS check failed: {e}")


def scheduled_dhcp_sync():
    """Scheduled DHCP lease sync for all enabled servers."""
    if not DHCP_ENABLED:
        return
    logger.info("Running scheduled DHCP sync")
    try:
        servers = dhcp_collector.get_servers()
        for server in servers:
            dhcp_collector.sync_leases(server['id'])
    except Exception as e:
        logger.error(f"Scheduled DHCP sync failed: {e}")


def scheduled_utilization_daily_aggregate():
    """Daily aggregation of utilization snapshots."""
    logger.info("Running daily utilization aggregation")
    try:
        utilization_collector.aggregate_daily()
    except Exception as e:
        logger.error(f"Daily utilization aggregation failed: {e}")


def scheduled_utilization_cleanup():
    """Weekly cleanup of old utilization snapshots."""
    logger.info("Running utilization snapshot cleanup")
    try:
        utilization_collector.cleanup_old_snapshots()
    except Exception as e:
        logger.error(f"Utilization cleanup failed: {e}")


def main():
    """Main scanner service loop."""
    logger.info("IPAM Subnet Scanner starting...")
    logger.info(f"Scan interval: {SCAN_INTERVAL}s, Timeout: {SCAN_TIMEOUT}s, "
                f"Concurrent: {SCAN_CONCURRENT}")

    # Schedule periodic subnet scans
    schedule.every(SCAN_INTERVAL).seconds.do(scheduled_subnet_scan)

    # Schedule Network Intelligence jobs
    if AD_ENABLED:
        schedule.every(AD_SYNC_INTERVAL).seconds.do(scheduled_ad_sync)
        logger.info(f"AD sync scheduled every {AD_SYNC_INTERVAL}s")
    schedule.every(DNS_CHECK_INTERVAL).seconds.do(scheduled_dns_check)
    logger.info(f"DNS check scheduled every {DNS_CHECK_INTERVAL}s")
    if DHCP_ENABLED:
        schedule.every(DHCP_SYNC_INTERVAL).seconds.do(scheduled_dhcp_sync)
        logger.info(f"DHCP sync scheduled every {DHCP_SYNC_INTERVAL}s")
    schedule.every().day.at("00:05").do(scheduled_utilization_daily_aggregate)
    schedule.every().week.do(scheduled_utilization_cleanup)
    logger.info("Utilization daily aggregate at 00:05, weekly cleanup scheduled")

    # Main processing loop
    while True:
        try:
            # Process queues
            process_scan_queue()
            process_ping_queue()
            process_ad_sync_queue()
            process_dns_check_queue()
            process_dhcp_sync_queue()
            process_conflict_queue()

            # Run scheduled tasks
            schedule.run_pending()

            # Small sleep to prevent CPU spinning
            time.sleep(0.1)

        except KeyboardInterrupt:
            logger.info("Scanner shutting down...")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            time.sleep(5)


if __name__ == '__main__':
    main()
