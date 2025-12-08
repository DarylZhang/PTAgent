# script/scanner/secret_hunter.py
import re
from typing import Optional, Dict


class SecretHunter:
    """
    被动扫描器：在 HTML/JS 源码中寻找硬编码的凭证。
    """

    # 简单的正则，实际可扩展
    PATTERNS = {
        "api_key": r"(?i)(api_key|apikey|secret)['\"\s:]+['\"]([a-zA-Z0-9-_]{20,})['\"]",
        "hardcoded_user": r"(?i)(user|username|email)['\"\s:]+['\"]([^'\"]+@[^'\"]+)['\"]",
        # 寻找注释里包含 password=... 的情况
        "comment_pwd": r""
    }

    @staticmethod
    def scan_content(url: str, content: str) -> Optional[Dict[str, str]]:
        """
        扫描文本内容，如果发现凭证，返回字典。
        """
        found = {}
        for key, pattern in SecretHunter.PATTERNS.items():
            matches = re.findall(pattern, content)
            for m in matches:
                # m 可能是 tuple，取决于正则 group
                value = m if isinstance(m, str) else str(m)
                # 简单去重，防止太长
                if len(value) < 200:
                    found[key] = value

        if found:
            print(f"[!] SecretHunter found potential creds in {url}: {found}")
            return found
        return None