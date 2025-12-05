# script/processor/asset_triager.py

from __future__ import annotations
from typing import Dict, List, Any, Optional
from dataclasses import asdict

# 假设你的 page_asset 定义在 script.scanner.page_asset
from scanner.page_asset import SiteAsset, PageAsset, ApiCall


class AssetTriager:
    """
    资产分诊器 (Asset Triager)

    职责：
    1. 接收 Scanner 生成的 SiteAsset (Raw Data)。
    2. 基于启发式逻辑 (Heuristics) 对 PageAsset 进行分类 (Interactive / Clue / Static)。
    3. 对不同类别的资产进行序列化 (Serialization)，生成适合喂给 LLM 的精简 JSON 上下文。
    """

    def __init__(self, site_asset: SiteAsset):
        self.site_asset = site_asset

        # 分诊结果容器
        self.buckets = {
            "interactive": [],  # 交互型：表单、登录、功能页
            "clues": [],  # 线索型：报错、配置泄露、目录索引
            "static": [],  # 静态型：纯文本、无交互页面
            "standalone_apis": []  # 纯 API：爬虫发现的独立接口
        }

    def triage(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        执行分诊逻辑的主入口。
        返回一个字典，包含分类且序列化后的数据，可直接作为 Prompt Context。
        """
        # 1. 处理所有页面
        for url, page in self.site_asset.pages.items():
            category = self._classify_page(page)
            serialized_data = self._serialize_page(page, category)
            self.buckets[category].append(serialized_data)

        # 2. 处理独立发现的 API (discovered_apis)
        # 这些通常都是高价值的 API 端点
        for api in self.site_asset.discovered_apis:
            self.buckets["standalone_apis"].append(self._serialize_api(api))

        return self.buckets

    # ==========================================
    # 核心逻辑：分类 (Classification)
    # ==========================================
    def _classify_page(self, page: PageAsset) -> str:
        """
        根据页面特征决定其类别。
        """
        # 1. 优先检查：线索型 (Clue)
        # 如果是报错页面，即使它看起来像 HTML，也没有交互价值，而是信息泄露价值
        if self._is_error_page(page):
            return "clues"

        # 2. 核心检查：交互型 (Interactive)
        # 只要有输入框、按钮(不仅是链接)、或者触发了 API 调用，就值得深入测试
        if page.inputs or page.api_calls:
            return "interactive"

        # 检查 clickables，排除纯导航链接
        # 如果有 <button> 或者 onclick 事件，视为交互
        has_real_action = any(
            c.tag == "button" or c.onclick is not None or c.role == "button"
            for c in page.clickables
        )
        if has_real_action:
            return "interactive"

        # 3. 再次检查线索型
        # 如果没有任何交互，但有注释 (可能包含 TODO) 或 Cookie，也可以算作线索
        if page.comments or page.cookies:
            return "clues"

        # 4. 兜底：静态/噪音 (Static)
        return "static"

    def _is_error_page(self, page: PageAsset) -> bool:
        """判断是否为报错页或非预期响应页"""
        # 特征 1: 标题包含 Error
        if page.title and "error" in page.title.lower():
            return True

        # 特征 2: 清洗后的 HTML 包含堆栈特征
        if page.cleaned_html:
            lower_html = page.cleaned_html.lower()
            keywords = [
                "stacktrace",
                "syntaxerror",
                "unexpected path",
                "internal server error",
                "exception at",
                "node_modules"
            ]
            for kw in keywords:
                if kw in lower_html:
                    return True

        return False

    def _is_login_page(self, page: PageAsset) -> bool:
        """辅助标签：是否像登录页"""
        url = page.url.lower()
        # 简单的关键词匹配
        if any(kw in url for kw in ["login", "signin", "auth", "admin"]):
            return True
        # 或者检查是否有 password 类型的输入框
        for inp in page.inputs:
            if inp.input_type == "password":
                return True
        return False

    # ==========================================
    # 核心逻辑：序列化 (Serialization / Formatting)
    # ==========================================
    def _serialize_page(self, page: PageAsset, category: str) -> Dict[str, Any]:
        """
        根据类别生成不同密度的 JSON 数据。
        """
        base_info = {
            "url": page.url,
            "title": page.title,
            "category": category
        }

        # --- A. 交互型：提供全量上下文 ---
        if category == "interactive":
            is_login = self._is_login_page(page)
            return {
                **base_info,
                "is_login_page": is_login,
                # 清洗后的 HTML 是理解页面结构的 best representation
                "structure_snapshot": page.cleaned_html,
                # 显式列出输入点，方便 LLM 引用 ID
                "inputs": [asdict(i) for i in page.inputs],
                # 列出已触发的 API，作为因果关系参考
                "observed_traffic": [
                    {
                        "method": api.method,
                        "url": api.url,
                        "body_sample": api.request_body[:200] if api.request_body else None
                    }
                    for api in page.api_calls
                ],
                # 提示：如果是登录页，LLM 应该重点关注
                "analysis_goal": "Check for SQLi, XSS, and Authentication Bypass." if is_login else "Check for Input Validation flaws and Logic vulnerabilities."
            }

        # --- B. 线索型：提供信息泄露证据 ---
        elif category == "clues":
            return {
                **base_info,
                # 报错页面通常包含 HTML 里的文字堆栈
                "error_content_sample": page.cleaned_html[:2000] if page.cleaned_html else "",
                "comments": page.comments,
                # 这种页面通常没有 inputs，不需要传
                "analysis_goal": "Identify Information Disclosure, Stack Traces, or Hidden Configs."
            }

        # --- C. 静态型：极简 ---
        else:  # static
            return {
                **base_info,
                "note": "Likely static content. Low priority."
            }

    def _serialize_api(self, api: ApiCall) -> Dict[str, Any]:
        """序列化独立 API"""
        return {
            "type": "standalone_api_endpoint",
            "url": api.url,
            "method": api.method,
            "status_code": api.response_status,
            # 如果有响应体（比如报错信息），也是重要线索
            "response_snippet": api.response_body[:500] if api.response_body else None,
            "analysis_goal": "Infer API usage. Try to construct a valid request (e.g., convert GET to POST)."
        }