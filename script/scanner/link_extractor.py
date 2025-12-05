import re
from typing import Set, List
from urllib.parse import urljoin, urlparse


class JsLinkExtractor:
    """
    专门用于从 JS 文本中提取 URL 和路径的提取器。
    采用“广撒网”策略，宁可错杀（404），不可放过（漏掉隐藏 API）。
    """

    # 1. 完整 URL 正则 (http://...)
    # 匹配 http/https 开头，非空白字符
    REGEX_URL = re.compile(r"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]+")

    # 2. 绝对路径正则 (以 / 开头)
    # 核心难点：避免匹配到除法 (a / b) 或注释 (//)
    # 策略：只匹配引号内的内容，且以 / 开头
    # 匹配: '/api/v1/user', "/login", `dashboard`
    REGEX_PATH = re.compile(r"['\"`](/[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]+)['\"`]")

    # 3. 忽略的静态资源后缀 (不需要爬取的资源)
    IGNORED_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf'
    }

    # 4. 忽略的常见非路由字符串 (MIME types, Selectors 等)
    IGNORED_PREFIXES = {
        '/app/', '/application/', '/text/', '/image/', '/video/', '/audio/',  # MIME types
        '//',  # 注释
    }

    @classmethod
    def extract_links(cls, content: str, base_url: str) -> Set[str]:
        """
        从任意文本（JS/HTML）中提取潜在的链接
        """
        found_links = set()

        # A. 提取完整 URL
        for match in cls.REGEX_URL.findall(content):
            # 简单清理：有时候正则会匹配到末尾的引号或分号
            clean_url = match.strip("'\",;)")
            if cls._is_valid_url(clean_url):
                found_links.add(clean_url)

        # B. 提取相对路径
        for match in cls.REGEX_PATH.findall(content):
            path = match  # findall 返回的是括号内的内容，即不含引号的 path

            # 过滤噪音
            if cls._is_noise(path):
                continue

            # 拼接为绝对路径
            absolute_url = urljoin(base_url, path)
            if cls._is_valid_url(absolute_url):
                found_links.add(absolute_url)

        return found_links

    @classmethod
    def _is_noise(cls, path: str) -> bool:
        """判断提取出的 path 是否是噪音"""
        path = path.lower()

        # 1. 长度过滤 (太短通常不是有效路由)
        if len(path) < 2:
            return True

        # 2. 前缀过滤 (过滤 MIME types 等)
        for prefix in cls.IGNORED_PREFIXES:
            if path.startswith(prefix):
                return True

        # 3. 后缀过滤 (过滤静态资源)
        # 简单的 split 判断
        if '.' in path:
            ext = path[path.rfind('.'):]
            if ext in cls.IGNORED_EXTENSIONS:
                return True

        # 4. 特殊字符过滤 (防止匹配到正则源码或 weird strings)
        # 如果包含换行符、不合法的 URL 字符，视为噪音
        if '\n' in path or '<' in path or '>' in path or '{' in path:
            return True

        return False

    @classmethod
    def _is_valid_url(cls, url: str) -> bool:
        """基本的 URL 格式校验"""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False