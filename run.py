#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import threading
import time
import uvicorn
import yaml

from shadowpot.logger import EventLogger
from shadowpot.server import SSHServer
from shadowpot.dashboard import create_dashboard_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("shadowpot.main")

def load_config(config_path: str) -> dict:
    if not os.path.exists(config_path):
        logger.error(f"Config file not found at {config_path}")
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def main():
    parser = argparse.ArgumentParser(description="ShadowPot - Hybrid SSH Honeypot & SIEM Telemetry Engine")
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--ssh-port", type=int, help="Override SSH port")
    parser.add_argument("--web-port", type=int, help="Override Web Dashboard port")
    parser.add_argument("--no-web", action="store_true", help="Disable Web Dashboard")
    parser.add_argument("--no-ssh", action="store_true", help="Disable SSH Honeypot (run dashboard only)")
    args = parser.parse_args()

    config = load_config(args.config)

    if args.ssh_port:
        config["honeypot"]["ssh_port"] = args.ssh_port
    if args.web_port:
        config["dashboard"]["port"] = args.web_port

    json_log = config.get("logging", {}).get("json_log_path", "logs/shadowpot.json")
    db_path = config.get("logging", {}).get("db_path", "data/shadowpot.db")
    event_logger = EventLogger(json_log_path=json_log, db_path=db_path)

    ssh_server = None
    if not args.no_ssh:
        ssh_server = SSHServer(config=config, event_logger=event_logger)
        ssh_thread = threading.Thread(target=ssh_server.start, daemon=True)
        ssh_thread.start()
        logger.info(f"[+] SSH Honeypot started on port {config['honeypot']['ssh_port']}")

    if not args.no_web and config.get("dashboard", {}).get("enabled", True):
        app = create_dashboard_app(event_logger=event_logger, config=config)
        host = config.get("dashboard", {}).get("host", "0.0.0.0")
        port = config.get("dashboard", {}).get("port", 8080)
        logger.info(f"[+] Starting Web Dashboard on http://{host}:{port}")
        try:
            uvicorn.run(app, host=host, port=port, log_level="warning")
        except KeyboardInterrupt:
            logger.info("Shutting down...")
    else:
        logger.info("[*] Running in headless mode. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")

    if ssh_server:
        ssh_server.stop()

if __name__ == "__main__":
    main()
