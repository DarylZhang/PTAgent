from abc import ABC, abstractmethod
from typing import Dict

from analysis.owasp_llm_analyzer import PotentialIssue
from attacker.attack_target import AttackResult
from utils.llm.base import LLMClient
from scanner.page_asset import SiteAsset


class AttackStrategy(ABC):
    """
    统一的抽象攻击接口，用于封装各种漏洞的攻击逻辑。
    """

    def __init__(self, llm_client: LLMClient):
        """初始化，传入 LLM 代理，以便在攻击过程中进行实时决策或生成载荷。"""
        self.llm = llm_client

    @abstractmethod
    def exploit(self,issue: PotentialIssue, site_asset: SiteAsset, session_context: Dict) -> AttackResult:
        """
        执行特定漏洞的攻击流程。

        参数:
            target: 攻击的目标 (InputField 或 ApiCall)。
            session_context: 当前会话的上下文（如：Cookies, Token, 客户端连接）。

        返回:
            AttackResult: 攻击尝试的结果。
        """
        pass

    # 可以添加其他抽象方法，如 check_vulnerability_hint, generate_payloads 等