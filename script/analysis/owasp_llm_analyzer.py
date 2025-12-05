# script/analysis/owasp_llm_analyzer.py

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import json
import logging

# 假设你的 LLM 客户端接口定义在这里
from script.llm.base import LLMClient


@dataclass
class PotentialIssue:
    # 漏洞位置描述
    location: str  # e.g., "Page: /login -> Input: email"

    # OWASP 类别
    owasp_category: str  # e.g., "A03: Injection"

    # 风险分析
    risk_reason: str  # e.g., "Input allows special characters and reflects in DOM..."

    # 抽象测试思路 (给后续 Payload Generator 用的)
    suggested_tests: List[str]

    # 关键：用于机器关联的 ID
    # 如果是页面上的输入框漏洞，填这个
    related_input_id: Optional[int] = None
    # 如果是 API 漏洞（如 IDOR），填这个 (虽然独立 API 没有 ID，但页面 API 有)
    related_api_url: Optional[str] = None

    # 漏洞置信度 (LLM 评估)
    confidence: str = "Medium"  # High, Medium, Low


@dataclass
class OwaspAnalysisResult:
    # 所有的潜在漏洞列表
    issues: List[PotentialIssue]

    def to_dict(self) -> Dict[str, Any]:
        return {"issues": [asdict(i) for i in self.issues]}


class OwaspTop10LLMAnalyzer:
    """
    LLM 分析器：
    接收 AssetTriager 的分诊结果，
    对 'interactive' 页面和 'standalone_apis' 进行逐个深度分析。
    """

    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client
        self.logger = logging.getLogger("LLM_Analyzer")

    def analyze(self, triaged_data: Dict[str, List[Dict[str, Any]]]) -> OwaspAnalysisResult:
        """
        主入口。
        triaged_data: AssetTriager.triage() 的返回值
        """
        all_issues: List[PotentialIssue] = []

        # 1. 分析交互型页面 (Interactive Pages) - 重中之重
        interactive_pages = triaged_data.get("interactive", [])
        print(f"[*] Analyzing {len(interactive_pages)} interactive pages with LLM...")

        for page_data in interactive_pages:
            try:
                page_issues = self._analyze_single_page(page_data)
                all_issues.extend(page_issues)
            except Exception as e:
                self.logger.error(f"Error analyzing page {page_data.get('url')}: {e}")

        # 2. 分析独立 API (Standalone APIs)
        standalone_apis = triaged_data.get("standalone_apis", [])
        if standalone_apis:
            print(f"[*] Analyzing {len(standalone_apis)} standalone APIs with LLM...")
            # 为了节省 Token，API 可以尝试 5 个一组批量分析，或者逐个分析
            # 这里演示逐个分析，准确率最高
            for api_data in standalone_apis:
                try:
                    api_issues = self._analyze_single_api(api_data)
                    all_issues.extend(api_issues)
                except Exception as e:
                    self.logger.error(f"Error analyzing API {api_data.get('url')}: {e}")

        # 3. (可选) 分析线索页面 (Clues) - 通常用于提取信息，而非直接找漏洞
        # 这里暂时跳过，或者可以写一个专门的 InfoExtractor

        return OwaspAnalysisResult(issues=all_issues)

    def _analyze_single_page(self, page_data: Dict[str, Any]) -> List[PotentialIssue]:
        """
        针对单个页面构建 Prompt 并请求 LLM
        """
        prompt = self._build_page_prompt(page_data)

        # 调用 LLM
        raw_response = self.llm_client.complete(prompt)

        # 解析结果
        return self._parse_llm_json(raw_response)

    def _analyze_single_api(self, api_data: Dict[str, Any]) -> List[PotentialIssue]:
        """
        针对单个 API 构建 Prompt 并请求 LLM
        """
        prompt = self._build_api_prompt(api_data)
        raw_response = self.llm_client.complete(prompt)
        return self._parse_llm_json(raw_response)

    def _build_page_prompt(self, page_data: Dict[str, Any]) -> str:
        """
        构建页面分析 Prompt
        """
        # 将字典转为 JSON 字符串，作为 Context
        context_json = json.dumps(page_data, indent=2, ensure_ascii=False)

        return f"""
You are a Web Security Expert specializing in OWASP Top 10 vulnerabilities.

### TARGET CONTEXT (JSON)
{context_json}

### TASK
Analyze the "structure_snapshot" (HTML), "inputs", and "observed_traffic" in the context above.
Identify potential security risks focusing on:
1. **Injection (SQLi/XSS)**: Look at inputs and URL parameters.
2. **Broken Access Control**: Look at the logic and API calls.
3. **Sensitive Data Exposure**: Look at comments or hidden fields.

### OUTPUT REQUIREMENT
Return a STRICT JSON object with a list of "issues". No markdown formatting.
Format:
{{
  "issues": [
    {{
      "location": "Descriptive location (e.g. Login Form -> Email Input)",
      "owasp_category": "A03: Injection",
      "risk_reason": "Explanation of why this is risky...",
      "suggested_tests": ["Try payload ' OR 1=1 --", "Check for error messages"],
      "related_input_id": 101 (Integer, MUST match the 'internal_id' in inputs list, or null),
      "related_api_url": "/api/login" (String, or null),
      "confidence": "High"
    }}
  ]
}}
If no obvious risks are found, return {{ "issues": [] }}.
"""

    def _build_api_prompt(self, api_data: Dict[str, Any]) -> str:
        """
        构建 API 分析 Prompt
        """
        context_json = json.dumps(api_data, indent=2, ensure_ascii=False)

        return f"""
You are a Web Security Expert. Analyze this discovered API endpoint.

### API CONTEXT (JSON)
{context_json}

### TASK
This is a standalone API endpoint discovered via JavaScript or fuzzing.
Determine how to abuse this endpoint.
Focus on:
1. **Method Tampering**: Can GET be POST?
2. **Missing Auth**: Is it an IDOR or Admin endpoint?
3. **Input Fuzzing**: What parameters does it likely accept?

### OUTPUT REQUIREMENT
Return a STRICT JSON object.
{{
  "issues": [
    {{
      "location": "API: {api_data.get('url')}",
      "owasp_category": "A01: Broken Access Control",
      "risk_reason": "Endpoint seems to be administrative...",
      "suggested_tests": ["Try accessing without cookies", "Change GET to POST"],
      "related_input_id": null,
      "related_api_url": "{api_data.get('url')}",
      "confidence": "Medium"
    }}
  ]
}}
"""

    def _parse_llm_json(self, raw_text: str) -> List[PotentialIssue]:
        """
        鲁棒的 JSON 解析器
        """
        try:
            # 有时候 LLM 会返回 ```json ... ```，需要清洗
            clean_text = raw_text.strip()
            if clean_text.startswith("```"):
                clean_text = clean_text.split("\n", 1)[1]
                clean_text = clean_text.rsplit("\n", 1)[0]
                if clean_text.startswith("json"):
                    clean_text = clean_text[4:].strip()

            data = json.loads(clean_text)

            issues = []
            for item in data.get("issues", []):
                issues.append(PotentialIssue(
                    location=item.get("location", "Unknown"),
                    owasp_category=item.get("owasp_category", "Unknown"),
                    risk_reason=item.get("risk_reason", ""),
                    suggested_tests=item.get("suggested_tests", []),
                    related_input_id=item.get("related_input_id"),
                    related_api_url=item.get("related_api_url"),
                    confidence=item.get("confidence", "Medium")
                ))
            return issues

        except json.JSONDecodeError:
            self.logger.warning(f"Failed to parse LLM response as JSON: {raw_text[:100]}...")
            return []
        except Exception as e:
            self.logger.error(f"Error parsing issues: {e}")
            return []