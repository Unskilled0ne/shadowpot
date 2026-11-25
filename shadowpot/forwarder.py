import logging
import threading
import time
import uuid
from typing import Dict, Any, Optional, List
import requests

logger = logging.getLogger("shadowpot.soar_forwarder")

class SOARForwarder:
    """
    Closed-loop integration forwarder for ShadowPot Honeypot.
    Monitors authentication failures and high-severity MITRE events,
    shipping actionable alerts to Aegis-SOAR for automated containment.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        soar_cfg = self.config.get("integrations", {}).get("soar", {})
        
        self.enabled = soar_cfg.get("enabled", True)
        self.primary_webhook = soar_cfg.get("webhook_url", "http://aegis-soar:8000/api/v1/alerts/webhook")
        self.primary_investigate = soar_cfg.get("investigate_url", "http://aegis-soar:8000/api/v1/alerts/investigate")
        self.threshold = soar_cfg.get("brute_force_threshold", 5)
        self.cooldown_seconds = soar_cfg.get("cooldown_seconds", 300)
        
        self.failed_attempts: Dict[str, int] = {}
        self.last_alert_time: Dict[str, float] = {}
        self._lock = threading.Lock()
        
        # Fallback endpoints if container hostname vs localhost varies
        self.webhook_endpoints = [
            self.primary_webhook,
            "http://127.0.0.1:8082/api/v1/alerts/webhook",
            "http://127.0.0.1:8000/api/v1/alerts/webhook",
            "http://localhost:8082/api/v1/alerts/webhook"
        ]
        self.investigate_endpoints = [
            self.primary_investigate,
            "http://127.0.0.1:8082/api/v1/alerts/investigate",
            "http://127.0.0.1:8000/api/v1/alerts/investigate",
            "http://localhost:8082/api/v1/alerts/investigate"
        ]

    def handle_event(self, event: Dict[str, Any]):
        if not self.enabled:
            return

        event_type = event.get("event_type")
        src_ip = event.get("source", {}).get("ip")
        if not src_ip:
            return

        now = time.time()

        # 1. SSH Brute Force Monitoring (T1110.001)
        if event_type in ("auth_failure", "auth_attempt"):
            should_alert = False
            with self._lock:
                self.failed_attempts[src_ip] = self.failed_attempts.get(src_ip, 0) + 1
                count = self.failed_attempts[src_ip]
                last_time = self.last_alert_time.get(src_ip, 0.0)

                if count >= self.threshold and (now - last_time) >= self.cooldown_seconds:
                    self.last_alert_time[src_ip] = now
                    should_alert = True

            if should_alert:
                threading.Thread(
                    target=self._dispatch_bruteforce_alert,
                    args=(src_ip, count, event),
                    daemon=True
                ).start()

        # 2. Ingress Tool Transfer / Payload Dropper (T1105)
        elif event_type == "payload_download" or event.get("mitre", {}).get("id") == "T1105":
            threading.Thread(
                target=self._dispatch_payload_alert,
                args=(src_ip, event),
                daemon=True
            ).start()

    def _post_with_fallback(self, endpoints: List[str], payload: Dict[str, Any]) -> bool:
        for url in endpoints:
            try:
                resp = requests.post(url, json=payload, timeout=2.5)
                if resp.status_code in (200, 201, 202):
                    logger.info(f"[SOAR Forwarder] Successfully forwarded alert to {url} (HTTP {resp.status_code})")
                    return True
                else:
                    logger.debug(f"[SOAR Forwarder] Endpoint {url} responded with {resp.status_code}")
            except Exception:
                continue
        return False

    def _dispatch_bruteforce_alert(self, src_ip: str, attempt_count: int, event: Dict[str, Any]):
        # Automated closed-loop containment playbook
        webhook_payload = {
            "playbook": "bruteforce_containment",
            "attacker_ip": src_ip,
            "attempt_count": attempt_count,
            "service": "ShadowPot SSH Honeypot"
        }
        success_wh = self._post_with_fallback(self.webhook_endpoints, webhook_payload)

        # Ingest into SOAR AI investigation & audit pipeline
        investigate_payload = {
            "alert_id": f"ALT-SHADOWPOT-{uuid.uuid4().hex[:6].upper()}",
            "source": "shadowpot",
            "timestamp": event.get("timestamp", ""),
            "event_type": "ssh_bruteforce",
            "severity": "HIGH",
            "rule_id": "100301",
            "rule_description": f"ShadowPot: High-frequency SSH brute-force attack (T1110.001) from {src_ip}",
            "source_ip": src_ip,
            "user_identity": event.get("auth", {}).get("username") if event.get("auth") else "unknown",
            "raw_log": f"MITRE T1110.001: {attempt_count} failed authentication attempts recorded in session {event.get('session_id')}",
            "metadata": {
                "attempt_count": attempt_count,
                "mitre_id": "T1110.001",
                "mitre_tactic": "Credential Access",
                "session_id": event.get("session_id"),
                "country": event.get("source", {}).get("country"),
                "closed_loop_action": "TRIGGERED" if success_wh else "QUEUED"
            }
        }
        self._post_with_fallback(self.investigate_endpoints, investigate_payload)

    def _dispatch_payload_alert(self, src_ip: str, event: Dict[str, Any]):
        extra = event.get("extra") or {}
        captured_files = extra.get("captured_files") or []
        
        file_hashes = []
        urls = []
        for cf in captured_files:
            if isinstance(cf, dict):
                if cf.get("sha256"):
                    file_hashes.append(cf["sha256"])
                elif cf.get("md5"):
                    file_hashes.append(cf["md5"])
                if cf.get("url"):
                    urls.append(cf["url"])

        investigate_payload = {
            "alert_id": f"ALT-SHADOWPOT-{uuid.uuid4().hex[:6].upper()}",
            "source": "shadowpot",
            "timestamp": event.get("timestamp", ""),
            "event_type": "payload_download",
            "severity": "CRITICAL",
            "rule_id": "100304",
            "rule_description": f"ShadowPot: Malware dropper / tool transfer detected (T1105) from {src_ip}",
            "source_ip": src_ip,
            "extracted_urls": urls,
            "file_hashes": file_hashes,
            "raw_log": f"Command executed: {event.get('command') or 'curl/wget dropper'}",
            "metadata": {
                "mitre_id": "T1105",
                "mitre_tactic": "Command and Control",
                "session_id": event.get("session_id"),
                "quarantine_files": captured_files
            }
        }
        self._post_with_fallback(self.investigate_endpoints, investigate_payload)
