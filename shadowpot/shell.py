import os
import re
import shlex
import time
from typing import Dict, Any, Tuple, Optional

PASSWD_CONTENT = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:104:111::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
mysql:x:110:116:MySQL Server,,,:/nonexistent:/bin/false
"""

SHADOW_CONTENT = """root:$6$vQ9Z8/K.$kF0lWlP5ZlK21P4H7d3x4qR1u2e4W8j5K6z7X8c9V0b1N2m3Q4w5E6r7T8y9U0i1O2p3A4s5D6f7G8h9J0k1L2:19820:0:99999:7:::
daemon:*:19820:0:99999:7:::
bin:*:19820:0:99999:7:::
sys:*:19820:0:99999:7:::
sync:*:19820:0:99999:7:::
games:*:19820:0:99999:7:::
man:*:19820:0:99999:7:::
lp:*:19820:0:99999:7:::
mail:*:19820:0:99999:7:::
news:*:19820:0:99999:7:::
uucp:*:19820:0:99999:7:::
proxy:*:19820:0:99999:7:::
www-data:*:19820:0:99999:7:::
backup:*:19820:0:99999:7:::
list:*:19820:0:99999:7:::
irc:*:19820:0:99999:7:::
gnats:*:19820:0:99999:7:::
nobody:*:19820:0:99999:7:::
ubuntu:$6$a7X3kL8P$e4J1N2m3Q4w5E6r7T8y9U0i1O2p3A4s5D6f7G8h9J0k1L2Z3x4c5v6b7n8m9Q0w1E2r3T4y5U6i7O8p9A0s1:19820:0:99999:7:::
mysql:!:19820:0:99999:7:::
"""

OS_RELEASE = """NAME="Ubuntu"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.4 LTS"
VERSION_ID="22.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
"""

CPUINFO = """processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 85
model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
stepping\t: 7
cpu MHz\t\t: 2499.998
cache size\t: 36608 KB
physical id\t: 0
siblings\t: 2
core id\t\t: 0
cpu cores\t: 2
fpu\t\t: yes
fpu_exception\t: yes
cpuid level\t: 13
wp\t\t: yes
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsave xsaves
bogomips\t: 4999.99
clflush size\t: 64
cache_alignment\t: 64
address sizes\t: 46 bits physical, 48 bits virtual
power management:
"""

MEMINFO = """MemTotal:        4016428 kB
MemFree:         1854212 kB
MemAvailable:    2841028 kB
Buffers:          124580 kB
Cached:          1125400 kB
SwapCached:            0 kB
Active:          1412580 kB
Inactive:         512400 kB
SwapTotal:             0 kB
SwapFree:              0 kB
"""

class EmulatedShell:
    def __init__(self, username: str = "root", hostname: str = "ubuntu-server-prod-01"):
        self.username = username
        self.hostname = hostname
        self.cwd = "/root" if username == "root" else f"/home/{username}"
        self.is_root = (username == "root")
        self.history = [
            "apt update && apt upgrade -y",
            "systemctl restart nginx",
            "tail -f /var/log/nginx/access.log",
            "netstat -tuln"
        ]
        self.virtual_files = {
            "/etc/passwd": PASSWD_CONTENT,
            "/etc/shadow": SHADOW_CONTENT,
            "/etc/os-release": OS_RELEASE,
            "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n",
            "/proc/cpuinfo": CPUINFO,
            "/proc/meminfo": MEMINFO,
            "/root/backup.sh": "#!/bin/bash\ntar -czf /var/backups/web.tar.gz /var/www/html\n",
            "/var/www/html/index.html": "<html><body><h1>Internal Portal Maintenance</h1></body></html>"
        }

    def get_prompt(self) -> str:
        symbol = "#" if self.is_root else "$"
        path_disp = "~" if self.cwd in ("/root", f"/home/{self.username}") else self.cwd
        return f"{self.username}@{self.hostname}:{path_disp}{symbol} "

    def execute_command(self, cmd_line: str) -> Tuple[str, bool]:
        """
        Processes command string and returns (output_text, should_exit).
        """
        cmd_line = cmd_line.strip()
        if not cmd_line:
            return "", False

        self.history.append(cmd_line)

        # Handle chaining (semi-colon or && or pipes)
        # Handle 'exit' / 'logout'
        if cmd_line in ("exit", "logout", "quit"):
            return "logout\n", True

        if cmd_line == "clear":
            return "\033[H\033[2J", False

        parts = cmd_line.split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        # Recon commands
        if cmd == "pwd":
            return f"{self.cwd}\n", False

        elif cmd == "whoami":
            return f"{self.username}\n", False

        elif cmd == "id":
            if self.is_root:
                return "uid=0(root) gid=0(root) groups=0(root)\n", False
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)\n", False

        elif cmd in ("uname", "uname -a"):
            if "-a" in args or cmd == "uname -a":
                return f"Linux {self.hostname} 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n", False
            elif "-r" in args:
                return "5.15.0-105-generic\n", False
            elif "-m" in args:
                return "x86_64\n", False
            return "Linux\n", False

        elif cmd == "hostname":
            return f"{self.hostname}\n", False

        elif cmd == "uptime":
            return " 16:40:12 up 14 days,  3:22,  1 user,  load average: 0.08, 0.03, 0.01\n", False

        elif cmd in ("ls", "ll"):
            return self._handle_ls(args), False

        elif cmd == "cd":
            target = args[0] if args else ("/root" if self.is_root else f"/home/{self.username}")
            if target == "~":
                self.cwd = "/root" if self.is_root else f"/home/{self.username}"
            elif target == "..":
                parent = os.path.dirname(self.cwd.rstrip("/"))
                self.cwd = parent if parent else "/"
            elif target.startswith("/"):
                self.cwd = target.rstrip("/") or "/"
            else:
                new_path = os.path.normpath(os.path.join(self.cwd, target))
                self.cwd = new_path
            return "", False

        elif cmd == "cat":
            if not args:
                return "", False
            target_file = args[0]
            if not target_file.startswith("/"):
                target_file = os.path.normpath(os.path.join(self.cwd, target_file))
            if target_file in self.virtual_files:
                return self.virtual_files[target_file] + "\n", False
            return f"cat: {args[0]}: No such file or directory\n", False

        elif cmd in ("ps", "ps aux", "ps -ef"):
            return self._handle_ps(), False

        elif cmd in ("netstat", "ss"):
            return self._handle_netstat(), False

        elif cmd in ("ifconfig", "ip"):
            return self._handle_ip(args), False

        elif cmd == "history":
            out = []
            for idx, item in enumerate(self.history, 1):
                out.append(f"  {idx:4d}  {item}")
            return "\n".join(out) + "\n", False

        elif cmd == "sudo":
            if self.is_root:
                if args:
                    return self.execute_command(" ".join(args))
                return "usage: sudo -h | -K | -k | -V\n", False
            return "[sudo] password for " + self.username + ": \n", False

        elif cmd in ("curl", "wget"):
            # Simulate network download progress
            url = args[-1] if args else "http://example.com"
            return f"Connecting to {url}... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: unspecified [application/octet-stream]\nSaving to: 'output'\n", False

        elif cmd in ("echo", "touch", "rm", "mkdir", "chmod", "chown"):
            # Acknowledge silently like standard unix
            return "", False

        # Fallback for unrecognized command
        return f"bash: {cmd}: command not found\n", False

    def _handle_ls(self, args) -> str:
        if self.cwd == "/root":
            return "backup.sh  .bashrc  .profile  .ssh\n"
        elif self.cwd == "/":
            return "bin   dev  home  lib32  libx32      media  opt   root  sbin  sys  usr\nboot  etc  lib   lib64  lost+found  mnt    proc  run   srv   tmp  var\n"
        elif self.cwd == "/var/www/html":
            return "index.html\n"
        elif self.cwd == "/etc":
            return "issue  os-release  passwd  shadow  hosts  hostname  resolv.conf  ssh  ssl\n"
        elif self.cwd == "/tmp":
            return "\n"
        return "\n"

    def _handle_ps(self) -> str:
        return """USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1 168432 11244 ?        Ss   Aug20   0:15 /sbin/init
root           2  0.0  0.0      0     0 ?        S    Aug20   0:00 [kthreadd]
root         412  0.0  0.2  72140 18450 ?        Ss   Aug20   0:02 /lib/systemd/systemd-journald
root         430  0.0  0.1  24128  6120 ?        Ss   Aug20   0:01 /lib/systemd/systemd-udevd
systemd+     590  0.0  0.2  26912 11984 ?        Ss   Aug20   0:03 /lib/systemd/systemd-resolved
root         720  0.0  0.1  15892  6420 ?        Ss   Aug20   0:05 /usr/sbin/sshd -D
www-data     810  0.0  0.3 142100 24100 ?        S    Aug20   0:12 nginx: worker process
mysql        905  0.1  2.1 1842000 184000 ?      Ssl  Aug20   2:45 /usr/sbin/mysqld
root        1024  0.0  0.1  14200  4120 pts/0    Ss   16:30   0:00 -bash
root        1055  0.0  0.0  11820  2400 pts/0    R+   16:40   0:00 ps aux
"""

    def _handle_netstat(self) -> str:
        return """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      720/sshd: /usr/sbin 
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      810/nginx: master p 
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      810/nginx: master p 
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      905/mysqld          
tcp6       0      0 :::22                   :::*                    LISTEN      720/sshd: /usr/sbin 
"""

    def _handle_ip(self, args) -> str:
        return """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:16:3e:4d:92:1f brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.150/24 brd 192.168.1.255 scope global dynamic eth0
       valid_lft 86200sec preferred_lft 86200sec
"""
