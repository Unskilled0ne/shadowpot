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
        
        self.failed_attempts: Dict[str, int] = {}
        self.alerted_ips: set = set()
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

        if event_type in ("auth_failure", "auth_attempt"):
            with self._lock:
                self.failed_attempts[src_ip] = self.failed_attempts.get(src_ip, 0) + 1
                count = self.failed_attempts[src_ip]

            if count >= self.threshold and src_ip not in self.alerted_ips:
                with self._lock:
                    self.alerted_ips.add(src_ip)
                
                # Asynchronously ship to Aegis-SOAR
                threading.Thread(
                    target=self._dispatch_bruteforce_alert,
                    args=(src_ip, count, event),
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
        # 1. Trigger automated closed-loop containment playbook
        webhook_payload = {
            "playbook": "bruteforce_containment",
            "attacker_ip": src_ip,
            "attempt_count": attempt_count,
            "service": "ShadowPot SSH Honeypot"
        }
        success_wh = self._post_with_fallback(self.webhook_endpoints, webhook_payload)

        # 2. Ingest into SOAR AI investigation & audit pipeline
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
