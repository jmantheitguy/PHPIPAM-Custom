"""
DHCP Lease Collector

Read-only access to DHCP servers to collect active leases
and correlate them against PHPIPAM allocations.

Supports: ISC DHCPD (file), Kea (file/database), Windows (JSON export), Infoblox (API).
"""

import os
import re
import json
import logging
from datetime import datetime

import mysql.connector

logger = logging.getLogger('collector.dhcp')

DHCP_ENABLED = os.getenv('DHCP_ENABLED', 'false').lower() == 'true'


class DHCPCollector:
    """Collects DHCP leases and correlates with PHPIPAM."""

    def __init__(self, db_connection_class, mysql_config):
        self.db_class = db_connection_class
        self.mysql_config = mysql_config

    def get_servers(self):
        """Get configured DHCP servers from database."""
        servers = []
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT * FROM dhcp_servers WHERE enabled = 1
                """)
                servers = cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to get DHCP servers: {e}")
        return servers

    def collect_leases(self, server):
        """Collect leases from a DHCP server based on its type and access method."""
        method = server['access_method']
        server_type = server['server_type']

        if method == 'file':
            if server_type == 'isc-dhcpd':
                return self._parse_isc_lease_file(server['lease_file_path'])
            elif server_type == 'kea':
                return self._parse_kea_lease_file(server['lease_file_path'])
            elif server_type == 'windows':
                return self._parse_windows_export(server['lease_file_path'])
        elif method == 'database':
            if server_type == 'kea':
                return self._query_kea_database(server)
        elif method == 'api':
            if server_type == 'infoblox':
                return self._query_infoblox_api(server)
            elif server_type == 'kea':
                return self._query_kea_api(server)

        logger.warning(f"Unsupported combination: {server_type}/{method}")
        return []

    def _parse_isc_lease_file(self, path):
        """Parse ISC DHCPD lease file (read-only)."""
        leases = []
        if not path or not os.path.exists(path):
            logger.error(f"Lease file not found: {path}")
            return leases

        try:
            with open(path, 'r') as f:
                content = f.read()

            # Parse lease blocks
            lease_pattern = re.compile(
                r'lease\s+([\d.]+)\s*\{(.*?)\}',
                re.DOTALL
            )

            for match in lease_pattern.finditer(content):
                ip = match.group(1)
                block = match.group(2)

                lease = {
                    'ip_address': ip,
                    'mac_address': None,
                    'hostname': None,
                    'lease_start': None,
                    'lease_end': None,
                    'lease_state': 'active',
                }

                # Extract MAC
                mac_match = re.search(
                    r'hardware\s+ethernet\s+([\da-fA-F:]+)', block)
                if mac_match:
                    lease['mac_address'] = mac_match.group(1).upper()

                # Extract hostname
                host_match = re.search(
                    r'client-hostname\s+"([^"]+)"', block)
                if host_match:
                    lease['hostname'] = host_match.group(1)

                # Extract timestamps
                start_match = re.search(
                    r'starts\s+\d+\s+([\d/]+\s+[\d:]+)', block)
                if start_match:
                    lease['lease_start'] = self._parse_isc_date(
                        start_match.group(1))

                end_match = re.search(
                    r'ends\s+\d+\s+([\d/]+\s+[\d:]+)', block)
                if end_match:
                    lease['lease_end'] = self._parse_isc_date(
                        end_match.group(1))

                # Check binding state
                state_match = re.search(
                    r'binding\s+state\s+(\w+)', block)
                if state_match:
                    state = state_match.group(1).lower()
                    if state == 'free':
                        lease['lease_state'] = 'released'
                    elif state == 'expired':
                        lease['lease_state'] = 'expired'
                    elif state == 'backup':
                        lease['lease_state'] = 'backup'

                leases.append(lease)

        except Exception as e:
            logger.error(f"Failed to parse ISC lease file: {e}")

        return leases

    def _parse_isc_date(self, date_str):
        """Parse ISC DHCPD date format."""
        try:
            return datetime.strptime(date_str, '%Y/%m/%d %H:%M:%S')
        except ValueError:
            return None

    def _parse_kea_lease_file(self, path):
        """Parse Kea CSV lease file (read-only)."""
        leases = []
        if not path or not os.path.exists(path):
            logger.error(f"Kea lease file not found: {path}")
            return leases

        try:
            with open(path, 'r') as f:
                header = None
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if header is None:
                        header = line.split(',')
                        continue

                    fields = line.split(',')
                    if len(fields) < len(header):
                        continue

                    row = dict(zip(header, fields))
                    leases.append({
                        'ip_address': row.get('address', ''),
                        'mac_address': row.get('hwaddr', '').upper() or None,
                        'hostname': row.get('hostname', '') or None,
                        'lease_start': None,
                        'lease_end': self._parse_kea_timestamp(
                            row.get('expire', '')),
                        'lease_state': 'active' if row.get('state', '0') == '0'
                                       else 'expired',
                        'subnet_mask': row.get('subnet_id', ''),
                    })
        except Exception as e:
            logger.error(f"Failed to parse Kea lease file: {e}")

        return leases

    def _parse_kea_timestamp(self, ts):
        """Parse Kea timestamp (epoch or ISO)."""
        if not ts:
            return None
        try:
            return datetime.utcfromtimestamp(int(ts))
        except (ValueError, OSError):
            try:
                return datetime.fromisoformat(ts)
            except ValueError:
                return None

    def _parse_windows_export(self, path):
        """Parse Windows DHCP JSON export (read-only)."""
        leases = []
        if not path or not os.path.exists(path):
            logger.error(f"Windows export not found: {path}")
            return leases

        try:
            with open(path, 'r') as f:
                data = json.load(f)

            for entry in data:
                leases.append({
                    'ip_address': entry.get('IPAddress', ''),
                    'mac_address': entry.get('ClientId', '').replace('-', ':').upper() or None,
                    'hostname': entry.get('HostName', '') or None,
                    'lease_start': None,
                    'lease_end': self._parse_windows_date(
                        entry.get('LeaseExpiryTime')),
                    'lease_state': 'active',
                })
        except Exception as e:
            logger.error(f"Failed to parse Windows export: {e}")

        return leases

    def _parse_windows_date(self, date_str):
        """Parse Windows date formats."""
        if not date_str:
            return None
        for fmt in ('%m/%d/%Y %H:%M:%S', '%Y-%m-%dT%H:%M:%S'):
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        return None

    def _query_kea_database(self, server):
        """Read-only query against Kea lease database."""
        leases = []
        try:
            kea_conn = mysql.connector.connect(
                host=server['db_host'],
                port=server.get('db_port') or 3306,
                user=server['db_user'],
                password=server['db_password'],
                database=server['db_name'],
            )
            cursor = kea_conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT address, HEX(hwaddr) as hwaddr, hostname,
                       expire, state, subnet_id
                FROM lease4
                WHERE state = 0
            """)
            for row in cursor.fetchall():
                # Convert integer address to dotted notation
                addr_int = row['address']
                ip = f"{(addr_int >> 24) & 0xFF}.{(addr_int >> 16) & 0xFF}." \
                     f"{(addr_int >> 8) & 0xFF}.{addr_int & 0xFF}"

                # Convert hex MAC
                hwaddr = row.get('hwaddr', '')
                mac = ':'.join(hwaddr[i:i+2] for i in range(0, len(hwaddr), 2)) \
                    if hwaddr else None

                leases.append({
                    'ip_address': ip,
                    'mac_address': mac.upper() if mac else None,
                    'hostname': row.get('hostname') or None,
                    'lease_end': row.get('expire'),
                    'lease_state': 'active' if row.get('state') == 0
                                   else 'expired',
                })
            kea_conn.close()
        except Exception as e:
            logger.error(f"Kea database query failed: {e}")

        return leases

    def _query_infoblox_api(self, server):
        """Read-only REST API query to Infoblox for leases."""
        import requests
        leases = []
        try:
            url = f"{server['api_url']}/lease"
            resp = requests.get(
                url,
                headers={'Authorization': f"Bearer {server['api_key']}"},
                verify=False,
                timeout=30,
                params={'_return_fields': 'address,hardware,client_hostname,'
                                          'starts,ends,binding_state'},
            )
            resp.raise_for_status()

            for entry in resp.json():
                leases.append({
                    'ip_address': entry.get('address', ''),
                    'mac_address': entry.get('hardware', '').upper() or None,
                    'hostname': entry.get('client_hostname') or None,
                    'lease_start': entry.get('starts'),
                    'lease_end': entry.get('ends'),
                    'lease_state': 'active' if entry.get('binding_state') == 'ACTIVE'
                                   else 'expired',
                })
        except Exception as e:
            logger.error(f"Infoblox API query failed: {e}")

        return leases

    def _query_kea_api(self, server):
        """Read-only query to Kea Control Agent API."""
        import requests
        leases = []
        try:
            url = server['api_url']
            payload = {
                'command': 'lease4-get-all',
                'service': ['dhcp4'],
            }
            resp = requests.post(url, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            if data and data[0].get('result') == 0:
                for lease in data[0].get('arguments', {}).get('leases', []):
                    leases.append({
                        'ip_address': lease.get('ip-address', ''),
                        'mac_address': lease.get('hw-address', '').upper() or None,
                        'hostname': lease.get('hostname') or None,
                        'lease_state': 'active' if lease.get('state') == 0
                                       else 'expired',
                    })
        except Exception as e:
            logger.error(f"Kea API query failed: {e}")

        return leases

    def correlate_with_phpipam(self, leases):
        """Match each lease against PHPIPAM ipaddresses table."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)

                for lease in leases:
                    cursor.execute("""
                        SELECT id, dns_name, mac,
                               INET_NTOA(ip_addr) as ip_address
                        FROM ipaddresses
                        WHERE ip_addr = INET_ATON(%s)
                        LIMIT 1
                    """, (lease['ip_address'],))

                    phpipam_row = cursor.fetchone()

                    if not phpipam_row:
                        lease['correlation_status'] = 'lease_only'
                        lease['phpipam_address_id'] = None
                        continue

                    lease['phpipam_address_id'] = phpipam_row['id']
                    lease['phpipam_hostname'] = phpipam_row.get('dns_name')
                    lease['phpipam_mac'] = phpipam_row.get('mac')

                    # Check MAC match
                    phpipam_mac = (phpipam_row.get('mac') or '').upper()
                    lease_mac = (lease.get('mac_address') or '').upper()

                    if phpipam_mac and lease_mac and phpipam_mac != lease_mac:
                        lease['correlation_status'] = 'mac_mismatch'
                    elif (phpipam_row.get('dns_name') and lease.get('hostname')
                          and phpipam_row['dns_name'].lower() != lease['hostname'].lower()):
                        lease['correlation_status'] = 'hostname_mismatch'
                    else:
                        lease['correlation_status'] = 'matched'

        except Exception as e:
            logger.error(f"PHPIPAM correlation failed: {e}")

        return leases

    def sync_leases(self, server_id):
        """Full sync: collect, correlate, store leases."""
        if not DHCP_ENABLED:
            logger.info("DHCP sync skipped - DHCP_ENABLED=false")
            return None

        # Get server config
        servers = self.get_servers()
        server = next((s for s in servers if s['id'] == server_id), None)
        if not server:
            logger.error(f"DHCP server {server_id} not found")
            return None

        sync_id = self._create_sync_record(server_id)
        self._update_sync_status(sync_id, 'running')

        try:
            # Collect leases
            leases = self.collect_leases(server)
            logger.info(f"Collected {len(leases)} leases from "
                        f"{server['name']} ({server['server_type']})")

            # Correlate
            leases = self.correlate_with_phpipam(leases)

            # Store
            self._store_leases(server_id, leases)

            # Stats
            matched = sum(1 for l in leases
                          if l.get('correlation_status') == 'matched')
            unmatched = sum(1 for l in leases
                           if l.get('correlation_status') == 'lease_only')
            mac_mm = sum(1 for l in leases
                         if l.get('correlation_status') == 'mac_mismatch')
            host_mm = sum(1 for l in leases
                          if l.get('correlation_status') == 'hostname_mismatch')

            self._update_sync_status(sync_id, 'completed',
                                     found=len(leases), matched=matched,
                                     unmatched=unmatched, mac_mm=mac_mm,
                                     host_mm=host_mm)

            # Update server last_sync
            self._update_server_sync(server_id, len(leases), 'success')

            logger.info(f"DHCP sync complete: {len(leases)} leases, "
                        f"{matched} matched, {unmatched} unmatched")
            return sync_id

        except Exception as e:
            logger.error(f"DHCP sync failed: {e}")
            self._update_sync_status(sync_id, 'failed', error=str(e))
            self._update_server_sync(server_id, 0, 'failed')
            return sync_id

    def _create_sync_record(self, server_id):
        """Create dhcp_sync_history record."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO dhcp_sync_history (server_id, status)
                    VALUES (%s, 'pending')
                """, (server_id,))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to create DHCP sync record: {e}")
            return None

    def _update_sync_status(self, sync_id, status, error=None,
                            found=0, matched=0, unmatched=0,
                            mac_mm=0, host_mm=0):
        """Update dhcp_sync_history record."""
        if not sync_id:
            return
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                if status == 'running':
                    cursor.execute("""
                        UPDATE dhcp_sync_history
                        SET status = 'running', started_at = NOW()
                        WHERE id = %s
                    """, (sync_id,))
                elif status == 'completed':
                    cursor.execute("""
                        UPDATE dhcp_sync_history
                        SET status = 'completed', completed_at = NOW(),
                            leases_found = %s, leases_matched = %s,
                            leases_unmatched = %s, mac_mismatches = %s,
                            hostname_mismatches = %s,
                            duration_seconds = TIMESTAMPDIFF(SECOND, started_at, NOW())
                        WHERE id = %s
                    """, (found, matched, unmatched, mac_mm, host_mm, sync_id))
                elif status == 'failed':
                    cursor.execute("""
                        UPDATE dhcp_sync_history
                        SET status = 'failed', completed_at = NOW(),
                            error_message = %s,
                            duration_seconds = TIMESTAMPDIFF(SECOND, started_at, NOW())
                        WHERE id = %s
                    """, (error, sync_id))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update DHCP sync status: {e}")

    def _update_server_sync(self, server_id, lease_count, status):
        """Update dhcp_servers last_sync info."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE dhcp_servers
                    SET last_sync = NOW(), last_sync_status = %s,
                        lease_count = %s
                    WHERE id = %s
                """, (status, lease_count, server_id))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update server sync info: {e}")

    def _store_leases(self, server_id, leases):
        """Store collected leases in dhcp_leases table."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()

                # Clear old leases for this server
                cursor.execute("""
                    DELETE FROM dhcp_leases WHERE server_id = %s
                """, (server_id,))

                for lease in leases:
                    cursor.execute("""
                        INSERT INTO dhcp_leases
                        (server_id, ip_address, mac_address, hostname,
                         lease_start, lease_end, lease_state,
                         correlation_status, phpipam_address_id,
                         phpipam_hostname, phpipam_mac, last_synced)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    """, (
                        server_id,
                        lease['ip_address'],
                        lease.get('mac_address'),
                        lease.get('hostname'),
                        lease.get('lease_start'),
                        lease.get('lease_end'),
                        lease.get('lease_state', 'active'),
                        lease.get('correlation_status', 'lease_only'),
                        lease.get('phpipam_address_id'),
                        lease.get('phpipam_hostname'),
                        lease.get('phpipam_mac'),
                    ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store leases: {e}")
