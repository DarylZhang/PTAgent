# script/executor/types.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List

# from script.scanner.web_attack_surface_scanner import (
#     AttackSurface,
#     InputField,
#     ApiCall,
# )
# from script.analysis.owasp_llm_analyzer import PotentialIssue


@dataclass
class TestContext:
    """
    针对某一个 PotentialIssue 的测试上下文。
    这里把 AttackSurface 中的原始对象也挂上，方便执行器使用。
    """
    base_url: str
    surface: AttackSurface
    issue: PotentialIssue

    # 如果是输入点相关的 issue（如 XSS、认证），会填这个字段
    input_field: Optional[InputField] = None

    # 如果是 API endpoint 相关的 issue（如未授权访问、SQLi），会填这个字段
    api_call: Optional[ApiCall] = None


@dataclass
class PlannedTest:
    """
    一次“具体要执行的测试”计划。
    未来由 LLM 或规则生成。
    """
    vuln_type: str          # "xss" / "sqli" / "auth" ...
    template_id: str        # 选用哪个 PayloadTemplate（在 registry 里的 ID）
    round_index: int = 1    # 第几轮测试
    note: Optional[str] = None  # 备注，比如“先尝试基础 <script> payload”


@dataclass
class TestResult:
    """
    某一次模板执行的结果。
    注意：一个模板里可能有多个 payload，本结构通常对应“某个具体 payload 的一次尝试”。
    """
    planned_test: PlannedTest
    payload: str

    success: bool
    evidence: str = ""          # 关键证据说明（页面内容片段、状态描述等）
    error: Optional[str] = None # 如果执行过程中发生异常，这里记录错误信息


@dataclass
class IssueTestSummary:
    """
    针对某一个 PotentialIssue 的整体测试摘要。
    未来可以作为写报告 / 存储结果的基础结构。
    """
    issue: PotentialIssue
    results: List[TestResult]
    final_status: str           # "vulnerable" / "not_observed" / "unknown"
    final_reason: str           # 人类可读解释（可以由 LLM 生成，也可以由规则生成）