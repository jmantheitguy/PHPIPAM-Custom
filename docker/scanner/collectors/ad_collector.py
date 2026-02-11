"""
AD Computers Collector

Read-only LDAP queries against Active Directory to sync computer objects,
resolve IPs, ping them, and cross-reference with PHPIPAM.
"""

import os
import logging
import socket
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import ldap
import ldap.controls
from ldap.controls import SimplePagedResultsControl

logger = logging.getLogger('collector.ad')

# AD configuration from environment
AD_ENABLED = os.getenv('AD_ENABLED', 'false').lower() == 'true'
AD_SERVER = os.getenv('AD_SERVER', '')
AD_BASE_DN = os.getenv('AD_BASE_DN', '')
AD_BIND_USER = os.getenv('AD_BIND_USER', '')
AD_BIND_PASSWORD = os.getenv('AD_BIND_PASSWORD', '')
AD_USE_TLS = os.getenv('AD_USE_TLS', 'true').lower() == 'true'
AD_STALE_THRESHOLD_DAYS = int(os.getenv('AD_STALE_THRESHOLD_DAYS', 30))
LDAP_PAGE_SIZE = 500

# Windows epoch offset: 100-nanosecond intervals from 1601-01-01 to 1970-01-01
WIN_EPOCH_OFFSET = 11644473600


def win_timestamp_to_datetime(win_ts):
    """Convert Windows FILETIME (100-ns intervals since 1601) to Python datetime."""
    if not win_ts or int(win_ts) == 0:
        return None
    try:
        unix_ts = (int(win_ts) / 10000000) - WIN_EPOCH_OFFSET
        if unix_ts < 0:
            return None
        return datetime.utcfromtimestamp(unix_ts)
    except (ValueError, OSError):
        return None


def parse_ad_datetime(val):
    """Parse AD generalized time format (e.g., '20240101120000.0Z')."""
    if not val:
        return None
    try:
        val_str = val.decode('utf-8') if isinstance(val, bytes) else val
        return datetime.strptime(val_str[:14], '%Y%m%d%H%M%S')
    except (ValueError, AttributeError):
        return None


class ADCollector:
    """Collects computer objects from Active Directory (read-only)."""

    COMPUTER_ATTRS = [
        'cn', 'dNSHostName', 'distinguishedName', 'operatingSystem',
        'operatingSystemVersion', 'lastLogonTimestamp', 'whenCreated',
        'whenChanged', 'pwdLastSet', 'description', 'memberOf',
        'userAccountControl',
    ]

    def __init__(self, db_connection_class, ping_func, mysql_config):
        self.db_class = db_connection_class
        self.ping_host = ping_func
        self.mysql_config = mysql_config
        self.conn = None

    def connect(self):
        """Establish read-only LDAP connection."""
        if not AD_ENABLED:
            logger.info("AD integration disabled")
            return False

        try:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            ldap.set_option(ldap.OPT_REFERRALS, 0)

            self.conn = ldap.initialize(AD_SERVER)
            self.conn.protocol_version = ldap.VERSION3
            self.conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 30)

            if AD_USE_TLS and AD_SERVER.startswith('ldap://'):
                self.conn.start_tls_s()

            self.conn.simple_bind_s(AD_BIND_USER, AD_BIND_PASSWORD)
            logger.info(f"Connected to AD server: {AD_SERVER}")
            return True
        except ldap.LDAPError as e:
            logger.error(f"LDAP connection failed: {e}")
            return False

    def disconnect(self):
        """Close LDAP connection."""
        if self.conn:
            try:
                self.conn.unbind_s()
            except ldap.LDAPError:
                pass
            self.conn = None

    def get_ou_tree(self, base_dn=None):
        """Read OU tree structure (read-only LDAP search)."""
        base = base_dn or AD_BASE_DN
        ous = []

        try:
            result = self.conn.search_s(
                base, ldap.SCOPE_SUBTREE,
                '(objectClass=organizationalUnit)',
                ['distinguishedName', 'name', 'ou']
            )

            for dn, attrs in result:
                if dn is None:
                    continue
                name = attrs.get('name', [b''])[0].decode('utf-8', errors='replace')
                # Calculate parent DN
                parts = dn.split(',', 1)
                parent_dn = parts[1] if len(parts) > 1 else None
                depth = dn.count(',OU=')

                ous.append({
                    'distinguished_name': dn,
                    'name': name,
                    'parent_dn': parent_dn,
                    'depth': depth,
                })

            logger.info(f"Found {len(ous)} OUs under {base}")
        except ldap.LDAPError as e:
            logger.error(f"OU tree search failed: {e}")

        return ous

    def get_computers(self, search_base=None):
        """Paged search for computer objects (read-only)."""
        base = search_base or AD_BASE_DN
        computers = []

        page_control = SimplePagedResultsControl(True, size=LDAP_PAGE_SIZE, cookie='')

        try:
            while True:
                msgid = self.conn.search_ext(
                    base, ldap.SCOPE_SUBTREE,
                    '(objectClass=computer)',
                    self.COMPUTER_ATTRS,
                    serverctrls=[page_control]
                )
                _rtype, rdata, _rmsgid, serverctrls = self.conn.result3(msgid)

                for dn, attrs in rdata:
                    if dn is None:
                        continue
                    computers.append(self._parse_computer(dn, attrs))

                # Check for next page
                controls = [c for c in serverctrls
                            if c.controlType == SimplePagedResultsControl.controlType]
                if controls and controls[0].cookie:
                    page_control.cookie = controls[0].cookie
                else:
                    break

            logger.info(f"Found {len(computers)} computers under {base}")
        except ldap.LDAPError as e:
            logger.error(f"Computer search failed: {e}")

        return computers

    def _parse_computer(self, dn, attrs):
        """Parse LDAP attributes into computer dict."""
        def attr_str(key):
            val = attrs.get(key, [b''])[0]
            return val.decode('utf-8', errors='replace') if val else None

        def attr_list(key):
            return [v.decode('utf-8', errors='replace') for v in attrs.get(key, [])]

        uac = int(attrs.get('userAccountControl', [b'0'])[0])
        is_enabled = not bool(uac & 0x2)

        last_logon = win_timestamp_to_datetime(
            attrs.get('lastLogonTimestamp', [b'0'])[0]
        )
        pwd_last_set = win_timestamp_to_datetime(
            attrs.get('pwdLastSet', [b'0'])[0]
        )

        # Calculate OU path from DN
        parts = dn.split(',', 1)
        ou_path = parts[1] if len(parts) > 1 else None

        return {
            'computer_name': attr_str('cn'),
            'distinguished_name': dn,
            'ou_path': ou_path,
            'dns_hostname': attr_str('dNSHostName'),
            'operating_system': attr_str('operatingSystem'),
            'os_version': attr_str('operatingSystemVersion'),
            'description': attr_str('description'),
            'is_enabled': is_enabled,
            'last_logon': last_logon,
            'when_created': parse_ad_datetime(attrs.get('whenCreated', [None])[0]),
            'when_changed': parse_ad_datetime(attrs.get('whenChanged', [None])[0]),
            'pwd_last_set': pwd_last_set,
            'member_of': attr_list('memberOf'),
        }

    def resolve_computer_ip(self, dns_hostname):
        """DNS forward lookup for computer hostname (read-only)."""
        if not dns_hostname:
            return None
        try:
            result = socket.getaddrinfo(dns_hostname, None, socket.AF_INET)
            if result:
                return result[0][4][0]
        except (socket.gaierror, socket.herror):
            pass
        return None

    def ping_computer(self, ip_address):
        """Ping a computer and return status."""
        if not ip_address:
            return 'unknown', None
        result = self.ping_host(ip_address)
        if result['alive']:
            return 'online', result.get('response_time')
        return 'offline', None

    def cross_reference_phpipam(self, computer):
        """Match computer against PHPIPAM ipaddresses table."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)

                # Try matching by IP
                if computer.get('ip_address'):
                    cursor.execute("""
                        SELECT id FROM ipaddresses
                        WHERE ip_addr = INET_ATON(%s) LIMIT 1
                    """, (computer['ip_address'],))
                    row = cursor.fetchone()
                    if row:
                        return row['id'], 'ip'

                # Try matching by hostname
                if computer.get('dns_hostname'):
                    cursor.execute("""
                        SELECT id FROM ipaddresses
                        WHERE dns_name = %s LIMIT 1
                    """, (computer['dns_hostname'],))
                    row = cursor.fetchone()
                    if row:
                        return row['id'], 'hostname'

                # Try matching by MAC
                if computer.get('mac_address'):
                    cursor.execute("""
                        SELECT id FROM ipaddresses
                        WHERE mac = %s LIMIT 1
                    """, (computer['mac_address'],))
                    row = cursor.fetchone()
                    if row:
                        return row['id'], 'mac'

        except Exception as e:
            logger.error(f"PHPIPAM cross-reference failed: {e}")

        return None, 'none'

    def detect_stale(self, computers):
        """Flag computers whose last logon exceeds the threshold."""
        threshold = datetime.utcnow() - timedelta(days=AD_STALE_THRESHOLD_DAYS)
        for comp in computers:
            if comp.get('last_logon') and comp['last_logon'] < threshold:
                comp['is_stale'] = True
                comp['stale_days'] = (datetime.utcnow() - comp['last_logon']).days
            else:
                comp['is_stale'] = False
                comp['stale_days'] = None
        return computers

    def detect_rogue(self):
        """Find network hosts not in AD (LEFT JOIN host_discovery vs ad_computers)."""
        rogue = []
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT hd.ip_address, hd.mac_address, hd.hostname,
                           hd.subnet_id, hd.last_seen
                    FROM host_discovery hd
                    LEFT JOIN ad_computers ac ON hd.ip_address = ac.ip_address
                    WHERE ac.id IS NULL
                    AND hd.status = 'active'
                    ORDER BY hd.last_seen DESC
                """)
                rogue = cursor.fetchall()
        except Exception as e:
            logger.error(f"Rogue detection query failed: {e}")
        return rogue

    def sync_computers(self, ou_dn=None):
        """Full sync workflow: query AD, resolve, ping, cross-reference, store."""
        if not AD_ENABLED:
            logger.info("AD sync skipped - AD_ENABLED=false")
            return None

        sync_id = self._create_sync_record('full' if not ou_dn else 'ou', ou_dn)

        try:
            self._update_sync_status(sync_id, 'running')

            if not self.connect():
                self._update_sync_status(sync_id, 'failed',
                                         error='LDAP connection failed')
                return sync_id

            # Sync OU tree
            ous = self.get_ou_tree(ou_dn)
            self._store_ou_tree(ous)

            # Get computers
            computers = self.get_computers(ou_dn)

            # Resolve IPs in parallel
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {
                    executor.submit(self.resolve_computer_ip, c['dns_hostname']): c
                    for c in computers
                }
                for future in as_completed(futures):
                    comp = futures[future]
                    comp['ip_address'] = future.result()

            # Ping in parallel
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {
                    executor.submit(self.ping_computer, c.get('ip_address')): c
                    for c in computers
                }
                for future in as_completed(futures):
                    comp = futures[future]
                    status, rtime = future.result()
                    comp['ping_status'] = status
                    comp['ping_response_time'] = rtime

            # Cross-reference with PHPIPAM
            for comp in computers:
                addr_id, match_type = self.cross_reference_phpipam(comp)
                comp['phpipam_address_id'] = addr_id
                comp['phpipam_match_type'] = match_type

            # Detect stale
            computers = self.detect_stale(computers)

            # Store results
            added, updated = self._store_computers(computers)
            stale_count = sum(1 for c in computers if c.get('is_stale'))

            # Detect rogue after sync
            rogue = self.detect_rogue()

            self._update_sync_status(sync_id, 'completed',
                                     found=len(computers), added=added,
                                     updated=updated, stale=stale_count,
                                     rogue=len(rogue))

            self.disconnect()
            logger.info(f"AD sync complete: {len(computers)} found, "
                        f"{added} added, {updated} updated, "
                        f"{stale_count} stale, {len(rogue)} rogue")

            return sync_id

        except Exception as e:
            logger.error(f"AD sync failed: {e}")
            self._update_sync_status(sync_id, 'failed', error=str(e))
            self.disconnect()
            return sync_id

    def _create_sync_record(self, sync_type, ou_dn=None):
        """Create ad_sync_history record."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO ad_sync_history (sync_type, ou_dn, status)
                    VALUES (%s, %s, 'pending')
                """, (sync_type, ou_dn))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to create sync record: {e}")
            return None

    def _update_sync_status(self, sync_id, status, error=None,
                            found=0, added=0, updated=0, stale=0, rogue=0):
        """Update ad_sync_history record."""
        if not sync_id:
            return
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                if status == 'running':
                    cursor.execute("""
                        UPDATE ad_sync_history
                        SET status = 'running', started_at = NOW()
                        WHERE id = %s
                    """, (sync_id,))
                elif status == 'completed':
                    cursor.execute("""
                        UPDATE ad_sync_history
                        SET status = 'completed', completed_at = NOW(),
                            computers_found = %s, computers_added = %s,
                            computers_updated = %s, stale_count = %s,
                            rogue_count = %s,
                            duration_seconds = TIMESTAMPDIFF(SECOND, started_at, NOW())
                        WHERE id = %s
                    """, (found, added, updated, stale, rogue, sync_id))
                elif status == 'failed':
                    cursor.execute("""
                        UPDATE ad_sync_history
                        SET status = 'failed', completed_at = NOW(),
                            error_message = %s,
                            duration_seconds = TIMESTAMPDIFF(SECOND, started_at, NOW())
                        WHERE id = %s
                    """, (error, sync_id))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update sync status: {e}")

    def _store_ou_tree(self, ous):
        """Store OU tree in ad_ou_cache."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                for ou in ous:
                    cursor.execute("""
                        INSERT INTO ad_ou_cache
                        (distinguished_name, name, parent_dn, depth, last_synced)
                        VALUES (%s, %s, %s, %s, NOW())
                        ON DUPLICATE KEY UPDATE
                        name = VALUES(name), parent_dn = VALUES(parent_dn),
                        depth = VALUES(depth), last_synced = NOW()
                    """, (ou['distinguished_name'], ou['name'],
                          ou['parent_dn'], ou['depth']))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store OU tree: {e}")

    def _store_computers(self, computers):
        """Store computers in ad_computers table. Returns (added, updated)."""
        import json
        added = 0
        updated = 0
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                for comp in computers:
                    member_of_json = json.dumps(comp.get('member_of', []))
                    cursor.execute("""
                        INSERT INTO ad_computers
                        (computer_name, distinguished_name, ou_path, dns_hostname,
                         operating_system, os_version, ip_address, description,
                         is_enabled, last_logon, when_created, when_changed,
                         pwd_last_set, member_of, ping_status, ping_response_time,
                         last_ping, phpipam_address_id, phpipam_match_type,
                         is_stale, stale_days, last_synced)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                                %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s, NOW())
                        ON DUPLICATE KEY UPDATE
                        computer_name = VALUES(computer_name),
                        ou_path = VALUES(ou_path),
                        dns_hostname = VALUES(dns_hostname),
                        operating_system = VALUES(operating_system),
                        os_version = VALUES(os_version),
                        ip_address = VALUES(ip_address),
                        description = VALUES(description),
                        is_enabled = VALUES(is_enabled),
                        last_logon = VALUES(last_logon),
                        when_changed = VALUES(when_changed),
                        pwd_last_set = VALUES(pwd_last_set),
                        member_of = VALUES(member_of),
                        ping_status = VALUES(ping_status),
                        ping_response_time = VALUES(ping_response_time),
                        last_ping = NOW(),
                        phpipam_address_id = VALUES(phpipam_address_id),
                        phpipam_match_type = VALUES(phpipam_match_type),
                        is_stale = VALUES(is_stale),
                        stale_days = VALUES(stale_days),
                        last_synced = NOW()
                    """, (
                        comp.get('computer_name'),
                        comp.get('distinguished_name'),
                        comp.get('ou_path'),
                        comp.get('dns_hostname'),
                        comp.get('operating_system'),
                        comp.get('os_version'),
                        comp.get('ip_address'),
                        comp.get('description'),
                        comp.get('is_enabled', True),
                        comp.get('last_logon'),
                        comp.get('when_created'),
                        comp.get('when_changed'),
                        comp.get('pwd_last_set'),
                        member_of_json,
                        comp.get('ping_status', 'unknown'),
                        comp.get('ping_response_time'),
                        comp.get('phpipam_address_id'),
                        comp.get('phpipam_match_type', 'none'),
                        comp.get('is_stale', False),
                        comp.get('stale_days'),
                    ))
                    if cursor.lastrowid:
                        added += 1
                    else:
                        updated += 1
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store computers: {e}")
        return added, updated

    def update_ou_computer_counts(self):
        """Update computer_count in ad_ou_cache."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE ad_ou_cache oc
                    SET computer_count = (
                        SELECT COUNT(*) FROM ad_computers ac
                        WHERE ac.ou_path = oc.distinguished_name
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update OU counts: {e}")
