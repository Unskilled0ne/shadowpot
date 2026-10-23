import os
import socket
import sys
import threading
import time
import uuid
import logging
from typing import Dict, Any, Optional

import paramiko
from shadowpot.logger import EventLogger
from shadowpot.shell import EmulatedShell
from shadowpot.threat_intel import enrich_ip
from shadowpot.trap import PayloadTrap

logger = logging.getLogger("shadowpot.server")

MOTD = """
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

System information as of Wed Sep  2 14:12:00 UTC 2026

  System load:  0.08               Processes:             115
  Usage of /:   34.2% of 40.00GB   Users logged in:       1
  Memory usage: 28%                IPv4 address for eth0: 192.168.1.150

Last login: Sun Sep  6 10:14:02 2026 from 192.168.1.45
"""

class HoneypotSSHInterface(paramiko.ServerInterface):
    def __init__(self, session_id: str, client_ip: str, client_port: int,
                 config: Dict[str, Any], event_logger: EventLogger, threat_info: Dict[str, Any]):
        self.session_id = session_id
        self.client_ip = client_ip
        self.client_port = client_port
        self.config = config
        self.logger = event_logger
        self.threat_info = threat_info

        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.authenticated = False
        self.channel_events: Dict[int, threading.Event] = {}
        self.channel_commands: Dict[int, str] = {}
        self.channel_ptys: Dict[int, bool] = {}

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            self.channel_events[chanid] = threading.Event()
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        self.password = password
        accept_all = self.config.get("auth", {}).get("accept_all", True)
        allowed = self.config.get("auth", {}).get("allowed_credentials", [])

        is_valid = accept_all or any(
            c.get("username") == username and c.get("password") == password
            for c in allowed
        )

        if is_valid:
            self.authenticated = True
            self.logger.log_event(
                event_type="auth_success",
                session_id=self.session_id,
                src_ip=self.client_ip,
                src_port=self.client_port,
                username=username,
                password=password,
                threat_intel=self.threat_info
            )
            return paramiko.AUTH_SUCCESSFUL
        else:
            self.logger.log_event(
                event_type="auth_failure",
                session_id=self.session_id,
                src_ip=self.client_ip,
                src_port=self.client_port,
                username=username,
                password=password,
                threat_intel=self.threat_info
            )
            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        key_fingerprint = key.get_fingerprint().hex()
        self.logger.log_event(
            event_type="auth_attempt",
            session_id=self.session_id,
            src_ip=self.client_ip,
            src_port=self.client_port,
            username=username,
            threat_intel=self.threat_info,
            extra={"key_type": key.get_name(), "fingerprint": key_fingerprint}
        )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        self.channel_ptys[channel.get_id()] = True
        return True

    def check_channel_shell_request(self, channel) -> bool:
        chanid = channel.get_id()
        if chanid in self.channel_events:
            self.channel_events[chanid].set()
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        chanid = channel.get_id()
        self.channel_commands[chanid] = command.decode("utf-8", errors="ignore")
        if chanid in self.channel_events:
            self.channel_events[chanid].set()
        return True


class SSHServer:
    def __init__(self, config: Dict[str, Any], event_logger: EventLogger):
        self.config = config
        self.logger = event_logger
        self.listen_host = config.get("honeypot", {}).get("listen_host", "0.0.0.0")
        self.ssh_port = config.get("honeypot", {}).get("ssh_port", 2222)
        self.banner = config.get("honeypot", {}).get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        self.host_key_path = config.get("honeypot", {}).get("host_key_path", "data/host_rsa.key")

        self.trap = PayloadTrap(
            quarantine_dir=config.get("emulation", {}).get("quarantine_dir", "quarantine"),
            enable_download=config.get("emulation", {}).get("quarantine_downloads", True)
        )
        self._host_key = self._load_or_generate_key()
        self._running = False
        self._sock: Optional[socket.socket] = None

    def _load_or_generate_key(self) -> paramiko.RSAKey:
        os.makedirs(os.path.dirname(self.host_key_path), exist_ok=True)
        if os.path.exists(self.host_key_path):
            return paramiko.RSAKey(filename=self.host_key_path)
        logger.info(f"Generating new RSA host key at {self.host_key_path}...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(self.host_key_path)
        return key

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.listen_host, self.ssh_port))
        self._sock.listen(100)
        self._running = True
        logger.info(f"[*] ShadowPot SSH Honeypot listening on {self.listen_host}:{self.ssh_port}")

        while self._running:
            try:
                client_sock, client_addr = self._sock.accept()
                client_ip, client_port = client_addr
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(client_sock, client_ip, client_port),
                    daemon=True
                )
                t.start()
            except Exception as e:
                if self._running:
                    logger.error(f"Error accepting connection: {e}")

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _handle_connection(self, client_sock: socket.socket, client_ip: str, client_port: int):
        session_id = str(uuid.uuid4())
        threat_info = enrich_ip(client_ip)
        user = "root"
        hostname = self.config.get("emulation", {}).get("hostname", "ubuntu-server-prod-01")
        shell = EmulatedShell(username=user, hostname=hostname)

        transport = None
        try:
            transport = paramiko.Transport(client_sock)
            transport.local_version = self.banner
            transport.add_server_key(self._host_key)

            interface = HoneypotSSHInterface(
                session_id=session_id,
                client_ip=client_ip,
                client_port=client_port,
                config=self.config,
                event_logger=self.logger,
                threat_info=threat_info
            )

            transport.start_server(server=interface)

            while transport.is_active():
                channel = transport.accept(timeout=1.0)
                if not channel:
                    continue

                chanid = channel.get_id()
                evt = interface.channel_events.get(chanid)
                if evt:
                    evt.wait(timeout=5)

                user = interface.username or "root"

                if chanid in interface.channel_commands:
                    cmd = interface.channel_commands[chanid].strip()
                    trap_analysis = self.trap.analyze_command(cmd)
                    self.logger.log_event(
                        event_type="command_exec",
                        session_id=session_id,
                        src_ip=client_ip,
                        src_port=client_port,
                        username=user,
                        command=cmd,
                        threat_intel=threat_info,
                        extra=trap_analysis
                    )
                    out, _ = shell.execute_command(cmd)
                    channel.send(out.replace("\n", "\r\n").encode("utf-8"))
                    channel.close()
                    continue

                channel.send(MOTD.replace("\n", "\r\n").encode("utf-8"))
                channel.send(shell.get_prompt().encode("utf-8"))

                buffer = ""
                while channel.active:
                    data = channel.recv(1024)
                    if not data:
                        break

                    for b in data:
                        char = chr(b)
                        if char in ("\r", "\n"):
                            channel.send(b"\r\n")
                            cmd = buffer.strip()
                            buffer = ""
                            if cmd:
                                trap_analysis = self.trap.analyze_command(cmd)
                                self.logger.log_event(
                                    event_type="command_exec",
                                    session_id=session_id,
                                    src_ip=client_ip,
                                    src_port=client_port,
                                    username=user,
                                    command=cmd,
                                    threat_intel=threat_info,
                                    extra=trap_analysis
                                )
                                output, should_exit = shell.execute_command(cmd)
                                if output:
                                    channel.send(output.replace("\n", "\r\n").encode("utf-8"))
                                if should_exit:
                                    channel.close()
                                    break
                            channel.send(shell.get_prompt().encode("utf-8"))
                        elif b in (8, 127):
                            if len(buffer) > 0:
                                buffer = buffer[:-1]
                                channel.send(b"\x08 \x08")
                        elif b == 3:
                            buffer = ""
                            channel.send(b"^C\r\n")
                            channel.send(shell.get_prompt().encode("utf-8"))
                        elif b == 4:
                            channel.close()
                            break
                        elif 32 <= b <= 126:
                            buffer += char
                            channel.send(char.encode("utf-8"))

        except Exception as e:
            logger.debug(f"Session {session_id} exception: {e}")
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass
            self.logger.log_event(
                event_type="session_close",
                session_id=session_id,
                src_ip=client_ip,
                src_port=client_port,
                threat_intel=threat_info
            )
