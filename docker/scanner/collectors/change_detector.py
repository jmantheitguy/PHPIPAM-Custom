"""
Network Change Detector

Detects network changes by comparing scan results against previous state.
Creates alerts based on configurable rules.
"""

import os
import json
import logging
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

import requests

logger = logging.getLogger('collector.change')

ALERT_WEBHOOK_URL = os.getenv('ALERT_WEBHOOK_URL', '')
SMTP_HOST = os.getenv('SMTP_HOST', '')
SMTP_PORT = int(os.getenv('SMTP_PORT', 25))
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASS = os.getenv('SMTP_PASS', '')


class ChangeDetector:
    """Detects network state changes and generates alerts."""

    def __init__(self, db_connection_class, mysql_config):
        self.db_class = db_connection_class
        self.mysql_config = mysql_config
        self._rules_cache = None
        self._rules_loaded_at = None

    def load_alert_rules(self):
        """Read enabled alert rules from database. Cache for 5 minutes."""
        now = datetime.utcnow()
        if (self._rules_cache and self._rules_loaded_at
                and (now - self._rules_loaded_at).seconds < 300):
            return self._rules_cache

        rules = {}
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT * FROM alert_rules WHERE enabled = 1
                """)
                for row in cursor.fetchall():
                    rules[row['alert_type']] = row
        except Exception as e:
            logger.error(f"Failed to load alert rules: {e}")

        self._rules_cache = rules
        self._rules_loaded_at = now
        return rules

    def get_previous_state(self, subnet_id):
        """Get most recent state entries for a subnet."""
        state = {}
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT ip_address, mac_address, hostname, is_alive
                    FROM network_state_history
                    WHERE subnet_id = %s
                    AND recorded_at = (
                        SELECT MAX(recorded_at) FROM network_state_history
                        WHERE subnet_id = %s
                    )
                """, (subnet_id, subnet_id))
                for row in cursor.fetchall():
                    state[row['ip_address']] = row
        except Exception as e:
            logger.error(f"Failed to get previous state: {e}")
        return state

    def save_current_state(self, subnet_id, scan_results, scan_id=None):
        """Save current scan results as state snapshot."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor()
                for result in scan_results:
                    cursor.execute("""
                        INSERT INTO network_state_history
                        (subnet_id, ip_address, mac_address, hostname,
                         is_alive, scan_id)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        subnet_id,
                        result['ip'],
                        result.get('mac_address'),
                        result.get('hostname'),
                        result.get('alive', False),
                        scan_id,
                    ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def compare_scan_results(self, subnet_id, current_results):
        """Compare current scan with previous state and generate alerts."""
        rules = self.load_alert_rules()
        previous = self.get_previous_state(subnet_id)

        if not previous:
            # First scan for this subnet, no comparison possible
            return []

        alerts = []
        current_map = {r['ip']: r for r in current_results}

        # Check current results against previous
        for ip, result in current_map.items():
            prev = previous.get(ip)

            if result.get('alive'):
                if prev is None:
                    # New device
                    if 'new_device' in rules:
                        alerts.append(self._build_alert(
                            'new_device', 'info', subnet_id,
                            ip=ip,
                            mac=result.get('mac_address'),
                            hostname=result.get('hostname'),
                            title=f"New device: {ip}",
                            details={'mac': result.get('mac_address'),
                                     'hostname': result.get('hostname')},
                        ))
                elif prev.get('mac_address') and result.get('mac_address'):
                    if prev['mac_address'] != result['mac_address']:
                        # New MAC on existing IP
                        if 'new_mac' in rules:
                            alerts.append(self._build_alert(
                                'new_mac', 'warning', subnet_id,
                                ip=ip,
                                mac=result.get('mac_address'),
                                title=f"New MAC on {ip}: "
                                      f"{prev['mac_address']} -> "
                                      f"{result['mac_address']}",
                                details={'old_mac': prev['mac_address'],
                                         'new_mac': result['mac_address']},
                            ))

                if not prev or not prev.get('is_alive'):
                    # Host came online
                    if prev and 'host_online' in rules:
                        alerts.append(self._build_alert(
                            'host_online', 'info', subnet_id,
                            ip=ip,
                            title=f"Host online: {ip}",
                        ))

        # Check for hosts that went offline
        for ip, prev in previous.items():
            if prev.get('is_alive') and ip not in current_map:
                if 'host_offline' in rules:
                    alerts.append(self._build_alert(
                        'host_offline', 'warning', subnet_id,
                        ip=ip,
                        mac=prev.get('mac_address'),
                        hostname=prev.get('hostname'),
                        title=f"Host offline: {ip}",
                    ))
            elif prev.get('is_alive') and not current_map.get(ip, {}).get('alive'):
                if 'host_offline' in rules:
                    alerts.append(self._build_alert(
                        'host_offline', 'warning', subnet_id,
                        ip=ip,
                        mac=prev.get('mac_address'),
                        hostname=prev.get('hostname'),
                        title=f"Host offline: {ip}",
                    ))

        # Check for device moved (same MAC in different subnet)
        if 'device_moved' in rules:
            alerts.extend(self._check_device_moved(subnet_id, current_results))

        # Store and notify
        for alert in alerts:
            self.create_alert(alert)

        return alerts

    def _check_device_moved(self, subnet_id, current_results):
        """Check if any MACs were previously seen in a different subnet."""
        alerts = []
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)
                for result in current_results:
                    mac = result.get('mac_address')
                    if not mac or not result.get('alive'):
                        continue

                    cursor.execute("""
                        SELECT subnet_id, ip_address
                        FROM network_state_history
                        WHERE mac_address = %s
                        AND subnet_id != %s
                        AND is_alive = 1
                        ORDER BY recorded_at DESC LIMIT 1
                    """, (mac, subnet_id))
                    prev = cursor.fetchone()

                    if prev:
                        alerts.append(self._build_alert(
                            'device_moved', 'warning', subnet_id,
                            ip=result['ip'],
                            mac=mac,
                            title=f"Device moved: {mac} from subnet "
                                  f"{prev['subnet_id']} ({prev['ip_address']}) "
                                  f"to subnet {subnet_id} ({result['ip']})",
                            details={
                                'old_subnet_id': prev['subnet_id'],
                                'old_ip': prev['ip_address'],
                                'new_subnet_id': subnet_id,
                                'new_ip': result['ip'],
                            },
                        ))
        except Exception as e:
            logger.error(f"Device moved check failed: {e}")
        return alerts

    def _build_alert(self, alert_type, severity, subnet_id,
                     ip=None, mac=None, hostname=None,
                     title='', details=None):
        """Build alert dict."""
        rules = self.load_alert_rules()
        rule = rules.get(alert_type, {})
        return {
            'alert_type': alert_type,
            'severity': rule.get('severity', severity),
            'subnet_id': subnet_id,
            'ip_address': ip,
            'mac_address': mac,
            'hostname': hostname,
            'title': title,
            'details': json.dumps(details) if details else None,
            'source_type': 'change_detector',
            'notification_method': rule.get('notification_method', 'db_only'),
            'email_recipients': rule.get('email_recipients'),
            'webhook_url': rule.get('webhook_url'),
            'cooldown_minutes': rule.get('cooldown_minutes', 60),
        }

    def create_alert(self, alert_data):
        """Check cooldown, insert alert into DB, send notifications."""
        try:
            with self.db_class(self.mysql_config) as conn:
                cursor = conn.cursor(dictionary=True)

                # Check cooldown
                cooldown = alert_data.get('cooldown_minutes', 60)
                cursor.execute("""
                    SELECT id FROM network_alerts
                    WHERE alert_type = %s AND ip_address = %s
                    AND created > DATE_SUB(NOW(), INTERVAL %s MINUTE)
                    LIMIT 1
                """, (alert_data['alert_type'],
                      alert_data.get('ip_address'),
                      cooldown))

                if cursor.fetchone():
                    logger.debug(f"Alert cooldown active for "
                                 f"{alert_data['alert_type']} "
                                 f"{alert_data.get('ip_address')}")
                    return None

                # Insert alert
                cursor.execute("""
                    INSERT INTO network_alerts
                    (alert_type, severity, subnet_id, ip_address,
                     mac_address, hostname, title, details, source_type)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    alert_data['alert_type'],
                    alert_data['severity'],
                    alert_data.get('subnet_id'),
                    alert_data.get('ip_address'),
                    alert_data.get('mac_address'),
                    alert_data.get('hostname'),
                    alert_data['title'],
                    alert_data.get('details'),
                    alert_data.get('source_type'),
                ))
                conn.commit()
                alert_id = cursor.lastrowid

                logger.info(f"Alert created: [{alert_data['severity']}] "
                            f"{alert_data['title']}")

                # Send notifications
                method = alert_data.get('notification_method', 'db_only')
                if method in ('webhook', 'email_and_webhook'):
                    self._send_webhook(alert_data)
                if method in ('email', 'email_and_webhook'):
                    self._send_email(alert_data)

                return alert_id

        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
            return None

    def _send_webhook(self, alert_data):
        """Send alert via webhook HTTP POST."""
        url = alert_data.get('webhook_url') or ALERT_WEBHOOK_URL
        if not url:
            return
        try:
            payload = {
                'alert_type': alert_data['alert_type'],
                'severity': alert_data['severity'],
                'title': alert_data['title'],
                'ip_address': alert_data.get('ip_address'),
                'mac_address': alert_data.get('mac_address'),
                'timestamp': datetime.utcnow().isoformat(),
            }
            requests.post(url, json=payload, timeout=10)
            logger.debug(f"Webhook sent to {url}")
        except Exception as e:
            logger.error(f"Webhook failed: {e}")

    def _send_email(self, alert_data):
        """Send alert via email."""
        recipients = alert_data.get('email_recipients')
        if not recipients or not SMTP_HOST:
            return
        try:
            msg = MIMEText(
                f"Alert: {alert_data['title']}\n"
                f"Type: {alert_data['alert_type']}\n"
                f"Severity: {alert_data['severity']}\n"
                f"IP: {alert_data.get('ip_address', 'N/A')}\n"
                f"Time: {datetime.utcnow().isoformat()}\n"
            )
            msg['Subject'] = f"[IPAM Alert] {alert_data['title']}"
            msg['From'] = SMTP_USER or 'ipam@localhost'
            msg['To'] = recipients

            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
                if SMTP_USER and SMTP_PASS:
                    smtp.login(SMTP_USER, SMTP_PASS)
                smtp.sendmail(msg['From'], recipients.split(','), msg.as_string())
            logger.debug(f"Email sent to {recipients}")
        except Exception as e:
            logger.error(f"Email send failed: {e}")
