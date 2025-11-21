# script/analysis/owasp_llm_analyzer.py

from dataclasses import dataclass, asdict
from typing import List, Dict, Any
import json

from script.scanner.attack_surface_view import LlmAttackSurfaceView
from script.llm.base import LLMClient

@dataclass
class PotentialIssue:
    location: str          # 如 "page:/#/login input#email" 或 "api:GET /rest/products/search"
    owasp_category: str    # 如 "A03: Injection"
    risk_reason: str       # LLM 解释为什么这里有风险
    suggested_tests: List[str]  # 高层次测试思路（不是具体 payload）
    related_input_id: int | None = None
    related_endpoint_id: int | None = None


@dataclass
class OwaspAnalysisResult:
    issues: List[PotentialIssue]

    def to_dict(self) -> Dict[str, Any]:
        return {"issues": [asdict(i) for i in self.issues]}

class OwaspTop10LLMAnalyzer:
    """
    使用 LLM 对攻击面做‘思考’：
    - 标记哪些输入点 / API 更可疑
    - 映射到 OWASP Top 10 分类
    - 产出高层次测试思路
    """

    def __init__(self, llm_client: LLMClient) -> None:
        self.llm_client = llm_client

    def analyze(self, view: LlmAttackSurfaceView) -> OwaspAnalysisResult:
        surface_dict = view.to_dict()
        prompt = self._build_prompt(surface_dict)

        raw = self.llm_client.complete(prompt)  # 这里是你接第三方 LLM 的位置
        data = json.loads(raw)                 # 假设 LLM 按我们要求返回 JSON

        issues: List[PotentialIssue] = []
        for item in data.get("issues", []):
            issues.append(
                PotentialIssue(
                    location=item["location"],
                    owasp_category=item["owasp_category"],
                    risk_reason=item["risk_reason"],
                    suggested_tests=item.get("suggested_tests", []),
                    related_input_id=item.get("related_input_id"),
                    related_endpoint_id=item.get("related_endpoint_id")
                )
            )

        return OwaspAnalysisResult(issues=issues)

    def _build_prompt(self, surface_dict: Dict[str, Any]) -> str:
        surface_json = json.dumps(surface_dict, ensure_ascii=False, indent=2)

        system_part = (
            "你是一名 Web 安全分析助手，你的任务不是直接发起攻击，"
            "而是根据给定的 Web 攻击面（页面、输入点、API 端点），"
            "标记出可能存在安全风险的‘位置’，按 OWASP Top 10 分类，并给出测试思路。\n"
            "请只输出 JSON，不要输出其它文字。\n"
        )

        user_part = f"""
下面是某个 Web 应用自动扫描得到的攻击面信息（JSON）：

注意：
- 每个输入点 inputs[i] 都有一个唯一的整数 id 字段。
- 每个 API 端点 endpoints[j] 也有一个唯一的整数 id 字段。
在输出 issues 时：
- 如果你针对的是某个页面输入点，请在 related_input_id 中填写对应的 id，related_endpoint_id 填 null。
- 如果你针对的是某个 API 端点，请在 related_endpoint_id 中填写对应的 id，related_input_id 填 null。
- 如果同时关联输入和接口，可以两个都填，但一般推荐只填一个最核心的。

{surface_json}

请你完成以下任务：

1. 找出你认为安全风险较大的页面输入点和 API endpoint。
2. 对每个点：
   - 填写 location 字符串：
       * 页面输入点格式： "page:<页面路径> <css_selector>"  例如 "page:/#/login input#email"
       * API 格式：       "api:<METHOD> <PATH>"              例如 "api:GET /rest/products/search"
   - 填写一个最相关的 OWASP Top 10 类别，例如：
       * "A01: Broken Access Control"
       * "A02: Cryptographic Failures"
       * "A03: Injection"
       * "A04: Insecure Design"
       * "A05: Security Misconfiguration"
       * "A06: Vulnerable and Outdated Components"
       * "A07: Identification and Authentication Failures"
       * "A08: Software and Data Integrity Failures"
       * "A09: Security Logging and Monitoring Failures"
       * "A10: Server-Side Request Forgery (SSRF)"
   - 填写 risk_reason：简要说明为什么你认为这里有风险（从是否可控输入、是否涉及敏感操作、是否可能注入等角度）。
   - 填写 1~3 条 suggested_tests，每一条是一个“高层次的测试思路”，
     比如“在该输入中尝试加入包含脚本标签的字符串，观察页面是否反射输出”，
     不要写出具体 payload 内容。

请严格按照下面 JSON 模板输出：

{{
  "issues": [
    {{
      "location": "page:/#/login input#email",
      "owasp_category": "A07: Identification and Authentication Failures",
      "risk_reason": "例如：该输入用于认证流程，可能存在弱认证或暴力破解风险（这里只是示例）",
      "suggested_tests": [
        "例如：尝试使用常见弱密码组合，观察登录错误提示信息是否暴露过多细节",
        "例如：尝试多次错误登录，观察是否存在账户锁定机制"
      ],
      "related_input_id": 0,
      "related_endpoint_id": null
    }},
    {{
      "location": "api:GET /rest/products/search",
      "owasp_category": "A03: Injection",
      "risk_reason": "例如：搜索接口接受用户可控的查询参数，可能存在注入风险（这里只是示例）",
      "suggested_tests": [
        "例如：在搜索参数中加入特殊字符，观察返回结果或错误信息是否异常"
      ],
      "related_input_id": null,
      "related_endpoint_id": 3
    }}
  ]
}}
"""
        return system_part + "\n\n" + user_part