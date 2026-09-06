import hashlib
import os
import re
import urllib.parse
from typing import Optional, Dict, Any
import requests

URL_REGEX = re.compile(r'https?://[^\s\'"|;<>()]+', re.IGNORECASE)
BASE64_EXEC_REGEX = re.compile(r'(?:base64\s+-d|openssl\s+enc\s+-d\s+-a)\s*\|\s*(?:ba|z)?sh', re.IGNORECASE)

class PayloadTrap:
    def __init__(self, quarantine_dir: str = "quarantine", enable_download: bool = True):
        self.quarantine_dir = quarantine_dir
        self.enable_download = enable_download
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def analyze_command(self, cmd: str) -> Optional[Dict[str, Any]]:
        """
        Inspects command for payload downloads or suspicious execution.
        """
        urls = URL_REGEX.findall(cmd)
        if not urls and not BASE64_EXEC_REGEX.search(cmd):
            return None

        result = {
            "suspicious": True,
            "detected_urls": urls,
            "has_base64_eval": bool(BASE64_EXEC_REGEX.search(cmd)),
            "captured_files": []
        }

        if self.enable_download and urls:
            for url in urls:
                captured = self._quarantine_url(url)
                if captured:
                    result["captured_files"].append(captured)

        return result

    def _quarantine_url(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Safely captures payload from URL with size and timeout restrictions.
        """
        try:
            parsed = urllib.parse.urlparse(url)
            # Only allow standard schemes
            if parsed.scheme not in ("http", "https"):
                return None

            # Stream download with 10MB limit and 5-second timeout
            with requests.get(url, stream=True, timeout=5.0, headers={"User-Agent": "Wget/1.21.3"}) as r:
                if r.status_code != 200:
                    return {"url": url, "status": f"HTTP {r.status_code}", "downloaded": False}

                sha256 = hashlib.sha256()
                md5 = hashlib.md5()
                total_size = 0
                chunks = []

                for chunk in r.iter_content(chunk_size=8192):
                    if not chunk:
                        break
                    total_size += len(chunk)
                    if total_size > 10 * 1024 * 1024:  # 10 MB maximum
                        break
                    sha256.update(chunk)
                    md5.update(chunk)
                    chunks.append(chunk)

                sha256_hex = sha256.hexdigest()
                md5_hex = md5.hexdigest()

                # Quarantine file
                dest_filename = f"payload_{sha256_hex[:16]}.quarantine"
                dest_path = os.path.join(self.quarantine_dir, dest_filename)

                with open(dest_path, "wb") as f:
                    for chunk in chunks:
                        f.write(chunk)

                return {
                    "url": url,
                    "sha256": sha256_hex,
                    "md5": md5_hex,
                    "size_bytes": total_size,
                    "quarantine_path": dest_path,
                    "downloaded": True
                }
        except Exception as e:
            return {"url": url, "error": str(e), "downloaded": False}
