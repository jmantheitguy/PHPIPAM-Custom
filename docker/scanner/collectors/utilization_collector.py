"""
Subnet Utilization Collector

Captures utilization snapshots per subnet, aggregates daily,
and supports cleanup of old raw data.
"""

import os
import logging
import math
from datetime import datetime, timedelta

logger = logging.getLogger('collector.utilization')

RETENTION_DAYS = int(os.getenv('UTILIZATION_RETENTION_DAYS', 90))


class UtilizationCollector:
    """Tracks subnet utilization over time."""

    def __init__(self, db_connection_class, mysql_config):
        self.db_class = db_connection_class
        self.mysql_config = mysql_config

    def capture_snapshot(self, subnet_id, scan_id=None):
        """Capture current utilization for a single subnet."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)

                # Get subnet details
                cursor.execute("""
                    SELECT id, subnet, mask FROM subnets
                    WHERE id = %s AND isFolder = 0
                """, (subnet_id,))
                subnet = cursor.fetchone()
                if not subnet:
                    return None

                mask = int(subnet['mask'])
                # Total usable hosts (exclude network and broadcast for /31+)
                if mask >= 31:
                    total_hosts = 2 ** (32 - mask)
                else:
                    total_hosts = (2 ** (32 - mask)) - 2

                if total_hosts <= 0:
                    return None

                # Used hosts (assigned in PHPIPAM)
                cursor.execute("""
                    SELECT COUNT(*) as cnt FROM ipaddresses
                    WHERE subnetId = %s
                """, (subnet_id,))
                used_hosts = cursor.fetchone()['cnt']

                # Active hosts (from most recent scan)
                cursor.execute("""
                    SELECT active_hosts FROM subnet_scans
                    WHERE subnet_id = %s AND status = 'completed'
                    ORDER BY end_time DESC LIMIT 1
                """, (subnet_id,))
                scan_row = cursor.fetchone()
                active_hosts = scan_row['active_hosts'] if scan_row else 0

                # Reserved hosts (state=3 in PHPIPAM)
                cursor.execute("""
                    SELECT COUNT(*) as cnt FROM ipaddresses
                    WHERE subnetId = %s AND state = 3
                """, (subnet_id,))
                reserved_hosts = cursor.fetchone()['cnt']

                # DHCP hosts (state=4 in PHPIPAM)
                cursor.execute("""
                    SELECT COUNT(*) as cnt FROM ipaddresses
                    WHERE subnetId = %s AND state = 4
                """, (subnet_id,))
                dhcp_hosts = cursor.fetchone()['cnt']

                free_hosts = max(0, total_hosts - used_hosts)
                utilization_pct = round((used_hosts / total_hosts) * 100, 2) \
                    if total_hosts > 0 else 0
                active_pct = round((active_hosts / total_hosts) * 100, 2) \
                    if total_hosts > 0 else 0

                # Insert snapshot
                cursor.execute("""
                    INSERT INTO subnet_utilization_snapshots
                    (subnet_id, scan_id, total_hosts, used_hosts, active_hosts,
                     reserved_hosts, dhcp_hosts, free_hosts,
                     utilization_percent, active_percent)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (subnet_id, scan_id, total_hosts, used_hosts,
                      active_hosts, reserved_hosts, dhcp_hosts, free_hosts,
                      utilization_pct, active_pct))
                conn.commit()

                logger.debug(f"Snapshot: subnet {subnet_id} - "
                             f"{utilization_pct}% utilized ({used_hosts}/{total_hosts})")

                return {
                    'subnet_id': subnet_id,
                    'total_hosts': total_hosts,
                    'used_hosts': used_hosts,
                    'active_hosts': active_hosts,
                    'free_hosts': free_hosts,
                    'utilization_percent': utilization_pct,
                    'active_percent': active_pct,
                }

        except Exception as e:
            logger.error(f"Snapshot capture failed for subnet {subnet_id}: {e}")
            return None

    def capture_all_snapshots(self, scan_id=None):
        """Capture snapshots for all non-folder subnets."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT id FROM subnets WHERE isFolder = 0
                """)
                subnets = cursor.fetchall()

            count = 0
            for subnet in subnets:
                result = self.capture_snapshot(subnet['id'], scan_id)
                if result:
                    count += 1

            logger.info(f"Captured utilization snapshots for {count} subnets")
            return count

        except Exception as e:
            logger.error(f"Failed to capture all snapshots: {e}")
            return 0

    def aggregate_daily(self, date=None):
        """Aggregate snapshots into daily summary."""
        if date is None:
            date = (datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%d')

        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)

                # Get distinct subnets that have snapshots for this date
                cursor.execute("""
                    SELECT DISTINCT subnet_id FROM subnet_utilization_snapshots
                    WHERE DATE(snapshot_time) = %s
                """, (date,))
                subnets = cursor.fetchall()

                for subnet in subnets:
                    sid = subnet['subnet_id']

                    cursor.execute("""
                        SELECT
                            AVG(utilization_percent) as avg_util,
                            MAX(utilization_percent) as max_util,
                            MIN(utilization_percent) as min_util,
                            AVG(active_percent) as avg_active,
                            MAX(active_percent) as max_active,
                            COUNT(*) as snap_count,
                            MAX(total_hosts) as total_hosts,
                            ROUND(AVG(used_hosts)) as used_avg,
                            ROUND(AVG(free_hosts)) as free_avg
                        FROM subnet_utilization_snapshots
                        WHERE subnet_id = %s AND DATE(snapshot_time) = %s
                    """, (sid, date))
                    agg = cursor.fetchone()

                    if agg and agg['snap_count'] > 0:
                        cursor.execute("""
                            INSERT INTO subnet_utilization_daily
                            (subnet_id, date, avg_utilization, max_utilization,
                             min_utilization, avg_active, max_active,
                             snapshot_count, total_hosts, used_hosts_avg,
                             free_hosts_avg)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON DUPLICATE KEY UPDATE
                            avg_utilization = VALUES(avg_utilization),
                            max_utilization = VALUES(max_utilization),
                            min_utilization = VALUES(min_utilization),
                            avg_active = VALUES(avg_active),
                            max_active = VALUES(max_active),
                            snapshot_count = VALUES(snapshot_count),
                            total_hosts = VALUES(total_hosts),
                            used_hosts_avg = VALUES(used_hosts_avg),
                            free_hosts_avg = VALUES(free_hosts_avg)
                        """, (
                            sid, date,
                            round(agg['avg_util'], 2),
                            round(agg['max_util'], 2),
                            round(agg['min_util'], 2),
                            round(agg['avg_active'], 2),
                            round(agg['max_active'], 2),
                            agg['snap_count'],
                            agg['total_hosts'],
                            agg['used_avg'],
                            agg['free_avg'],
                        ))

                conn.commit()
                logger.info(f"Daily aggregation complete for {date}: "
                            f"{len(subnets)} subnets")

        except Exception as e:
            logger.error(f"Daily aggregation failed for {date}: {e}")

    def cleanup_old_snapshots(self, retention_days=None):
        """Purge raw snapshots older than retention period. Keep daily aggregates."""
        days = retention_days or RETENTION_DAYS
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM subnet_utilization_snapshots
                    WHERE snapshot_time < DATE_SUB(NOW(), INTERVAL %s DAY)
                """, (days,))
                deleted = cursor.rowcount
                conn.commit()
                logger.info(f"Cleaned up {deleted} old utilization snapshots "
                            f"(>{days} days)")
        except Exception as e:
            logger.error(f"Snapshot cleanup failed: {e}")
