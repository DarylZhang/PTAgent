from dataclasses import dataclass
from typing import Union, Dict

from scanner.page_asset import InputField, ApiCall

# 攻击目标可以是 InputField 或 ApiCall
AttackTarget = Union[InputField, ApiCall]


@dataclass
class AttackResult:
    """代表一次攻击尝试的结果。"""

    success: bool  # 攻击是否成功
    vulnerability_type: str  # 成功利用的漏洞类型 (e.g., 'XSS', 'SQLi')
    severity: str  # 漏洞评级 (e.g., 'High', 'Medium')
    proof_of_concept: str  # 成功的攻击载荷/PoC代码
    request_snapshot: Dict  # 成功请求的详情 (Headers, Body等)
    response_snapshot: str  # 成功利用后的响应内容快照
    details: str = ""  # 攻击过程的详细日志或备注