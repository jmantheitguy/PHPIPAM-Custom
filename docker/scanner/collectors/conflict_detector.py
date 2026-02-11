"""
IP Conflict Detector

Uses scapy for ARP-based detection of multiple MACs claiming the same IP.
Integrates with network_alerts for notification.
"""

import os
import json
import logging
import ipaddress
from datetime import datetime
from collections import defaultdict

from scapy.all import ARP, Ether, srp, conf

logger = logging.getLogger('collector.conflict')

SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', 2))

# Suppress scapy warnings
conf.verb = 0


def load_oui_vendor(mac):
    """OUI vendor lookup from arp-scan database."""
    oui = mac.upper().replace(':', '')[:6]
    oui_file = '/usr/share/arp-scan/ieee-oui.txt'
    try:
        with open(oui_file, 'r') as f:
            for line in f:
                if line.startswith(oui):
                    parts = line.strip().split('\t', 1)
                    if len(parts) > 1:
                        return parts[1]
    except FileNotFoundError:
        pass
    return None


class ConflictDetector:
    """Detects IP conflicts via ARP scanning."""

    def __init__(self, db_connection_class, mysql_config):
        self.db_class = db_connection_class
        self.mysql_config = mysql_config

    def scan_for_conflicts(self, subnet_cidr):
        """
        Send ARP requests to subnet, collect responses.
        Flag IPs where multiple MACs respond.
        """
        logger.info(f"Scanning for IP conflicts in {subnet_cidr}")

        try:
            network = ipaddress.ip_network(subnet_cidr, strict=False)
        except ValueError as e:
            logger.error(f"Invalid subnet: {e}")
            return []

        # Build ARP request packet
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))

        # Send and collect responses
        ip_mac_map = defaultdict(list)

        try:
            answered, _ = srp(arp_request, timeout=SCAN_TIMEOUT, retry=2, verbose=0)

            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc.upper()
                if mac not in ip_mac_map[ip]:
                    ip_mac_map[ip].append(mac)

        except Exception as e:
            logger.error(f"ARP scan failed for {subnet_cidr}: {e}")
            return []

        # Find conflicts (IPs with more than one MAC)
        conflicts = []
        for ip, macs in ip_mac_map.items():
            if len(macs) >= 2:
                conflicts.append({
                    'ip_address': ip,
                    'mac_1': macs[0],
                    'mac_1_vendor': load_oui_vendor(macs[0]),
                    'mac_2': macs[1],
                    'mac_2_vendor': load_oui_vendor(macs[1]),
                    'detection_method': 'arp_scan',
                })

        logger.info(f"Found {len(conflicts)} IP conflicts in {subnet_cidr}")
        return conflicts

    def compare_with_previous(self, subnet_id, current_results):
        """Compare current MAC-IP mappings against network_state_history."""
        conflicts = []
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)

                for result in current_results:
                    if not result.get('mac_address') or not result.get('alive'):
                        continue

                    # Check if this IP had a different MAC in previous scan
                    cursor.execute("""
                        SELECT mac_address FROM network_state_history
                        WHERE subnet_id = %s AND ip_address = %s
                        AND mac_address IS NOT NULL
                        AND mac_address != %s
                        ORDER BY recorded_at DESC LIMIT 1
                    """, (subnet_id, result['ip'], result['mac_address']))

                    row = cursor.fetchone()
                    if row:
                        conflicts.append({
                            'ip_address': result['ip'],
                            'mac_1': row['mac_address'],
                            'mac_1_vendor': load_oui_vendor(row['mac_address']),
                            'mac_2': result['mac_address'],
                            'mac_2_vendor': load_oui_vendor(result['mac_address']),
                            'detection_method': 'scan_comparison',
                        })

        except Exception as e:
            logger.error(f"Compare with previous failed: {e}")

        return conflicts

    def store_conflict(self, conflict, subnet_id=None):
        """Store detected conflict in ip_conflicts and create alert."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()

                # Check if this conflict already exists and is active
                cursor.execute("""
                    SELECT id FROM ip_conflicts
                    WHERE ip_address = %s AND status = 'active'
                    AND ((mac_1 = %s AND mac_2 = %s) OR (mac_1 = %s AND mac_2 = %s))
                    LIMIT 1
                """, (conflict['ip_address'],
                      conflict['mac_1'], conflict['mac_2'],
                      conflict['mac_2'], conflict['mac_1']))

                existing = cursor.fetchone()

                if existing:
                    # Update last_detected
                    cursor.execute("""
                        UPDATE ip_conflicts SET last_detected = NOW()
                        WHERE id = %s
                    """, (existing[0],))
                else:
                    # Insert new conflict
                    cursor.execute("""
                        INSERT INTO ip_conflicts
                        (subnet_id, ip_address, mac_1, mac_1_vendor, mac_1_hostname,
                         mac_2, mac_2_vendor, mac_2_hostname, detection_method)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        subnet_id,
                        conflict['ip_address'],
                        conflict['mac_1'],
                        conflict.get('mac_1_vendor'),
                        conflict.get('mac_1_hostname'),
                        conflict['mac_2'],
                        conflict.get('mac_2_vendor'),
                        conflict.get('mac_2_hostname'),
                        conflict.get('detection_method', 'arp_scan'),
                    ))
                    conflict_id = cursor.lastrowid

                    # Create network alert
                    cursor.execute("""
                        INSERT INTO network_alerts
                        (alert_type, severity, subnet_id, ip_address,
                         title, details, source_type, source_id)
                        VALUES ('ip_conflict', 'critical', %s, %s, %s, %s,
                                'ip_conflicts', %s)
                    """, (
                        subnet_id,
                        conflict['ip_address'],
                        f"IP conflict: {conflict['ip_address']} claimed by "
                        f"{conflict['mac_1']} and {conflict['mac_2']}",
                        json.dumps(conflict),
                        conflict_id,
                    ))
                    alert_id = cursor.lastrowid

                    # Link alert back to conflict
                    cursor.execute("""
                        UPDATE ip_conflicts SET alert_id = %s WHERE id = %s
                    """, (alert_id, conflict_id))

                conn.commit()

        except Exception as e:
            logger.error(f"Failed to store conflict: {e}")

    def check_resolved(self, subnet_cidr):
        """Re-scan active conflicts; mark resolved if only one MAC responds."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)

                cursor.execute("""
                    SELECT id, ip_address, mac_1, mac_2
                    FROM ip_conflicts WHERE status = 'active'
                """)
                active = cursor.fetchall()

                if not active:
                    return

                # Quick ARP scan
                current = self.scan_for_conflicts(subnet_cidr)
                conflict_ips = {c['ip_address'] for c in current}

                for conflict in active:
                    if conflict['ip_address'] not in conflict_ips:
                        cursor.execute("""
                            UPDATE ip_conflicts
                            SET status = 'resolved', resolved_at = NOW()
                            WHERE id = %s
                        """, (conflict['id'],))
                        logger.info(f"Conflict resolved: {conflict['ip_address']}")

                conn.commit()

        except Exception as e:
            logger.error(f"Conflict resolution check failed: {e}")

    def process_scan_results(self, subnet_id, subnet_cidr, scan_results):
        """Called after scan_subnet() to check for conflicts."""
        # Method 1: ARP-based detection
        arp_conflicts = self.scan_for_conflicts(subnet_cidr)
        for conflict in arp_conflicts:
            self.store_conflict(conflict, subnet_id)

        # Method 2: Compare with previous scan state
        comparison_conflicts = self.compare_with_previous(subnet_id, scan_results)
        for conflict in comparison_conflicts:
            self.store_conflict(conflict, subnet_id)

        # Check if existing conflicts resolved
        self.check_resolved(subnet_cidr)

        return len(arp_conflicts) + len(comparison_conflicts)
