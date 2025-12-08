from dataclasses import dataclass, field
from typing import Dict


@dataclass
class AttackResult:
    """代表一次攻击尝试的结果。"""

    success: bool  # 必填：结果必须有成败
    vulnerability_type: str  # 必填：测的啥漏洞
    proof_of_concept: str  # 必填：没成功就是空字符串

    # --- 将以下字段改为带有默认值的可选字段 ---

    severity: str = "N/A"  # 默认为 N/A

    # 注意：对于 Dict 和 List，必须用 field(default_factory=...)
    request_snapshot: Dict = field(default_factory=dict)

    response_snapshot: str = ""

    details: str = ""