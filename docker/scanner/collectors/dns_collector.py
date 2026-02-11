"""
DNS Reconciliation Collector

Forward/reverse DNS checks against PHPIPAM hostnames.
Flags mismatches between DNS records and PHPIPAM data.
All DNS queries are read-only.
"""

import os
import json
import logging
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dns.reversename
import dns.exception

logger = logging.getLogger('collector.dns')

DNS_SERVERS = [s.strip() for s in os.getenv('DNS_SERVERS', '').split(',') if s.strip()]
DNS_TIMEOUT = 5


class DNSReconciler:
    """Performs DNS reconciliation against PHPIPAM records."""

    def __init__(self, db_connection_class, mysql_config):
        self.db_class = db_connection_class
        self.mysql_config = mysql_config
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = DNS_TIMEOUT
        self.resolver.lifetime = DNS_TIMEOUT
        if DNS_SERVERS:
            self.resolver.nameservers = DNS_SERVERS

    def forward_lookup(self, hostname, dns_server=None):
        """Resolve hostname to IP (read-only DNS query)."""
        resolver = self._get_resolver(dns_server)
        try:
            start = time.time()
            answers = resolver.resolve(hostname, 'A')
            elapsed = (time.time() - start) * 1000
            ips = [str(rdata) for rdata in answers]
            return ips, elapsed
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return [], 0
        except Exception as e:
            logger.debug(f"Forward lookup failed for {hostname}: {e}")
            return [], 0

    def reverse_lookup(self, ip_address, dns_server=None):
        """Resolve IP to hostname via PTR record (read-only DNS query)."""
        resolver = self._get_resolver(dns_server)
        try:
            start = time.time()
            rev_name = dns.reversename.from_address(ip_address)
            answers = resolver.resolve(rev_name, 'PTR')
            elapsed = (time.time() - start) * 1000
            hostnames = [str(rdata).rstrip('.') for rdata in answers]
            return hostnames, elapsed
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return [], 0
        except Exception as e:
            logger.debug(f"Reverse lookup failed for {ip_address}: {e}")
            return [], 0

    def _get_resolver(self, dns_server=None):
        """Get resolver, optionally with specific DNS server."""
        if dns_server:
            r = dns.resolver.Resolver()
            r.timeout = DNS_TIMEOUT
            r.lifetime = DNS_TIMEOUT
            r.nameservers = [dns_server]
            return r
        return self.resolver

    def check_address(self, ip_address, phpipam_hostname, dns_server=None):
        """
        Full DNS check for a single address.
        Returns mismatch type and details.
        """
        result = {
            'ip_address': ip_address,
            'phpipam_hostname': phpipam_hostname,
            'forward_result': None,
            'reverse_result': None,
            'mismatch_type': 'none',
            'dns_server': dns_server or (DNS_SERVERS[0] if DNS_SERVERS else None),
            'response_time_ms': 0,
        }

        # Reverse lookup: IP -> hostname
        rev_hostnames, rev_time = self.reverse_lookup(ip_address, dns_server)
        result['response_time_ms'] = rev_time

        if rev_hostnames:
            result['reverse_result'] = rev_hostnames[0]

        # If PHPIPAM has no hostname
        if not phpipam_hostname:
            if rev_hostnames:
                result['mismatch_type'] = 'no_phpipam_hostname'
            return result

        # Forward lookup: hostname -> IP
        fwd_ips, fwd_time = self.forward_lookup(phpipam_hostname, dns_server)
        result['response_time_ms'] = max(result['response_time_ms'], fwd_time)

        if fwd_ips:
            result['forward_result'] = fwd_ips[0]

        # Determine mismatch type
        has_ptr = len(rev_hostnames) > 0
        has_a = len(fwd_ips) > 0
        fwd_matches = ip_address in fwd_ips if fwd_ips else False
        rev_matches = any(
            phpipam_hostname.lower() in h.lower()
            for h in rev_hostnames
        ) if rev_hostnames else False

        if not has_ptr and not has_a:
            result['mismatch_type'] = 'both_mismatch'
        elif not has_ptr:
            result['mismatch_type'] = 'no_ptr'
        elif not has_a:
            result['mismatch_type'] = 'no_a_record'
        elif not fwd_matches and not rev_matches:
            result['mismatch_type'] = 'both_mismatch'
        elif not fwd_matches:
            result['mismatch_type'] = 'forward_mismatch'
        elif not rev_matches:
            result['mismatch_type'] = 'reverse_mismatch'
        else:
            result['mismatch_type'] = 'none'

        return result

    def reconcile_subnet(self, subnet_id, batch_id=None):
        """Check all addresses in a subnet."""
        addresses = self._get_subnet_addresses(subnet_id)
        if not addresses:
            logger.info(f"No addresses to check in subnet {subnet_id}")
            return []

        logger.info(f"DNS check: {len(addresses)} addresses in subnet {subnet_id}")

        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(
                    self.check_address,
                    addr['ip_address'],
                    addr['dns_name']
                ): addr
                for addr in addresses
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    result['subnet_id'] = subnet_id
                    result['batch_id'] = batch_id
                    results.append(result)
                except Exception as e:
                    logger.error(f"DNS check failed: {e}")

        # Store results
        self._store_results(results)

        mismatch_count = sum(1 for r in results if r['mismatch_type'] != 'none')
        logger.info(f"DNS check complete for subnet {subnet_id}: "
                    f"{mismatch_count}/{len(results)} mismatches")

        return results

    def reconcile_all(self, batch_id=None):
        """Check all subnets where DNS resolution is enabled."""
        subnets = self._get_dns_subnets()
        if not subnets:
            logger.info("No subnets configured for DNS checking")
            return

        batch_id = batch_id or self._create_batch('all')
        self._update_batch_status(batch_id, 'running')

        total_checks = 0
        total_mismatches = 0

        for subnet in subnets:
            results = self.reconcile_subnet(subnet['id'], batch_id)
            total_checks += len(results)
            total_mismatches += sum(
                1 for r in results if r['mismatch_type'] != 'none'
            )

        self._update_batch_status(batch_id, 'completed',
                                  total_checks=total_checks,
                                  mismatches=total_mismatches)
        return batch_id

    def _get_subnet_addresses(self, subnet_id):
        """Get IP addresses from PHPIPAM for a subnet."""
        addresses = []
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT id, INET_NTOA(ip_addr) as ip_address, dns_name
                    FROM ipaddresses
                    WHERE subnetId = %s
                """, (subnet_id,))
                addresses = cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to get subnet addresses: {e}")
        return addresses

    def _get_dns_subnets(self):
        """Get subnets with DNS resolution enabled."""
        subnets = []
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT id, subnet, mask
                    FROM subnets
                    WHERE resolveDNS = 1 AND isFolder = 0
                """)
                subnets = cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to get DNS subnets: {e}")
        return subnets

    def _create_batch(self, scope, subnet_id=None):
        """Create dns_check_batches record."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO dns_check_batches
                    (scope, subnet_id, status, dns_server)
                    VALUES (%s, %s, 'pending', %s)
                """, (scope, subnet_id,
                      DNS_SERVERS[0] if DNS_SERVERS else None))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to create DNS batch: {e}")
            return None

    def _update_batch_status(self, batch_id, status,
                             total_checks=0, mismatches=0, error=None):
        """Update dns_check_batches record."""
        if not batch_id:
            return
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                if status == 'running':
                    cursor.execute("""
                        UPDATE dns_check_batches
                        SET status = 'running', started_at = NOW()
                        WHERE id = %s
                    """, (batch_id,))
                elif status == 'completed':
                    cursor.execute("""
                        UPDATE dns_check_batches
                        SET status = 'completed', completed_at = NOW(),
                            total_checks = %s, mismatches_found = %s,
                            duration_seconds = TIMESTAMPDIFF(SECOND, started_at, NOW())
                        WHERE id = %s
                    """, (total_checks, mismatches, batch_id))
                elif status == 'failed':
                    cursor.execute("""
                        UPDATE dns_check_batches
                        SET status = 'failed', completed_at = NOW(),
                            error_message = %s,
                            duration_seconds = TIMESTAMPDIFF(SECOND, started_at, NOW())
                        WHERE id = %s
                    """, (error, batch_id))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update batch status: {e}")

    def _store_results(self, results):
        """Store DNS check results."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                for r in results:
                    cursor.execute("""
                        INSERT INTO dns_checks
                        (batch_id, subnet_id, ip_address, phpipam_hostname,
                         forward_result, reverse_result, mismatch_type,
                         dns_server, response_time_ms)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        r.get('batch_id'),
                        r.get('subnet_id'),
                        r['ip_address'],
                        r.get('phpipam_hostname'),
                        r.get('forward_result'),
                        r.get('reverse_result'),
                        r['mismatch_type'],
                        r.get('dns_server'),
                        r.get('response_time_ms'),
                    ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store DNS results: {e}")
