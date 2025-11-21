# script/payload/payload_registry.py

from __future__ import annotations

import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PayloadTemplate:
    """
    一个 payload 模板，对应 xss.yml 里的一条记录。
    例子（xss.yml）：

    - id: xss_basic_script_1
      vuln_type: xss
      name: Basic <script> XSS payload
      description: ...
      payloads:
        - "<script>alert(1)</script>"
      preferred_contexts:
        - html_body
      risk_level: medium
    """

    id: str
    vuln_type: str           # "xss" / "sqli" / ...
    name: str
    description: str
    payloads: List[str] = field(default_factory=list)
    preferred_contexts: List[str] = field(default_factory=list)
    risk_level: str = "medium"   # low / medium / high


class PayloadTemplateRegistry:
    """
    负责加载和管理所有 payload 模板。

    内部按 vuln_type 分组，例如：
      _by_vuln_type["xss"] = [PayloadTemplate, ...]
    同时也维护一个按 id 的索引：
      _by_id["xss_basic_script_1"] = PayloadTemplate(...)
    """

    def __init__(self) -> None:
        self._by_vuln_type: Dict[str, List[PayloadTemplate]] = {}
        self._by_id: Dict[str, PayloadTemplate] = {}

    # ---------------------------
    # 加载单个 YAML 文件
    # 支持两种格式：
    #  1) 顶层是列表（你现在的 xss.yml 就是这种）
    #  2) 顶层是 dict，包含 {category: xss, templates: [...]}
    # ---------------------------
    def load_from_file(self, file_path: str) -> None:
        if not file_path.endswith((".yml", ".yaml")):
            return

        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            return

        # 1) 顶层是列表：直接当作模板列表
        if isinstance(data, list):
            templates_data = data
            default_category: Optional[str] = None

        # 2) 顶层是 dict：兼容另一种写法 {category, templates}
        elif isinstance(data, dict) and "templates" in data:
            templates_data = data["templates"]
            default_category = data.get("category")
        else:
            # 其他结构暂时不支持
            return

        for tmpl in templates_data:
            # 尝试从模板自身拿 vuln_type；如果没有，就用顶层 category；再不行给个 unknown
            vuln_type = (tmpl.get("vuln_type") or default_category or "unknown").lower()

            payloads = tmpl.get("payloads") or []
            if isinstance(payloads, str):
                payloads = [payloads]

            pt = PayloadTemplate(
                id=tmpl["id"],
                vuln_type=vuln_type,
                name=tmpl.get("name", tmpl["id"]),
                description=tmpl.get("description", ""),
                payloads=payloads,
                preferred_contexts=tmpl.get("preferred_contexts", []) or [],
                risk_level=tmpl.get("risk_level", "medium"),
            )

            # 加入按 id 索引
            self._by_id[pt.id] = pt

            # 加入按 vuln_type 分组
            bucket = self._by_vuln_type.setdefault(vuln_type, [])
            bucket.append(pt)

    # ---------------------------
    # 扫描目录并加载所有 yml
    # ---------------------------
    def load_from_directory(self, dir_path: str) -> None:
        if not os.path.isdir(dir_path):
            return
        for file_name in os.listdir(dir_path):
            full_path = os.path.join(dir_path, file_name)
            if os.path.isfile(full_path):
                self.load_from_file(full_path)

    # ---------------------------
    # 查询接口
    # ---------------------------

    def get_templates_for_vuln(self, vuln_type: str) -> List[PayloadTemplate]:
        """按漏洞类型（xss/sqli/…）获取模板列表。"""
        return list(self._by_vuln_type.get(vuln_type.lower(), []))

    # 兼容你之前写的 get_by_category("xss")
    def get_by_category(self, category: str) -> List[PayloadTemplate]:
        return self.get_templates_for_vuln(category)

    def get_template_by_id(self, template_id: str) -> Optional[PayloadTemplate]:
        """根据模板 ID 精确获取一个模板对象。"""
        return self._by_id.get(template_id)

    def list_vuln_types(self) -> List[str]:
        """返回当前已有模板的所有 vuln_type 列表。"""
        return list(self._by_vuln_type.keys())