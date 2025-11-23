# # script/executor/xss_executor.py

# from __future__ import annotations

# from typing import List

# from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

# from script.executor.attack_executor import AttackExecutor
# from script.executor.types import TestContext, PlannedTest, TestResult
# from script.payload.payload_registry import PayloadTemplate
# from script.scanner.web_attack_surface_scanner import InputField


# class XssAttackExecutor(AttackExecutor):
#     """
#     专门处理 XSS（尤其是存储型 XSS）的执行器。

#     简化版逻辑：
#       1. 打开含有 input/textarea 的页面
#       2. 注入 payload
#       3. 尝试提交表单
#       4. 重新加载页面
#       5. 判断页面内容是否包含 payload 字符串片段
#     """

#     def __init__(self, headless: bool = True, timeout_ms: int = 15000) -> None:
#         self.headless = headless
#         self.timeout_ms = timeout_ms

#     # ---------------------------
#     # AttackExecutor 接口实现
#     # ---------------------------

#     def supports_vuln_type(self, vuln_type: str) -> bool:
#         return vuln_type.lower() == "xss"

#     def execute(
#         self,
#         context: TestContext,
#         planned_test: PlannedTest,
#         template: PayloadTemplate,
#     ) -> List[TestResult]:
#         """
#         对模板内的每个 payload 进行一次注入尝试。
#         返回每个 payload 的 TestResult。
#         """
#         if context.input_field is None:
#             raise ValueError("XssAttackExecutor requires context.input_field to be set")

#         results: List[TestResult] = []

#         input_field: InputField = context.input_field

#         with sync_playwright() as p:
#             browser = p.chromium.launch(headless=self.headless)
#             page = browser.new_page()

#             for payload in template.payloads:
#                 planned = planned_test  # 这里复用同一个 PlannedTest，payload 在结果里区分

#                 try:
#                     # 1. 打开页面
#                     page.goto(input_field.page_url, wait_until="networkidle", timeout=self.timeout_ms)

#                     # 2. 找到输入框
#                     el = page.query_selector(input_field.css_selector)
#                     if not el:
#                         results.append(
#                             TestResult(
#                                 planned_test=planned,
#                                 payload=payload,
#                                 success=False,
#                                 evidence=f"Input element not found: selector={input_field.css_selector}",
#                             )
#                         )
#                         continue

#                     # 3. 填写 payload
#                     try:
#                         el.fill(payload)
#                     except Exception:
#                         # 某些元素不支持 fill，可以尝试 type
#                         el.click()
#                         page.keyboard.type(payload)

#                     # 4. 尝试提交表单
#                     self._submit_form(page)

#                     # 5. 再次加载页面（简化：重新访问同一 URL）
#                     page.goto(input_field.page_url, wait_until="networkidle", timeout=self.timeout_ms)

#                     # 6. 检查页面内容是否包含 payload 片段
#                     html = page.content()

#                     # 简化的判定：直接看 payload 字符串是否出现在返回的 HTML 中
#                     if payload in html:
#                         success = True
#                         evidence = "Payload string found in rendered HTML (possible stored XSS)."
#                     else:
#                         success = False
#                         evidence = "Payload not found in rendered HTML."

#                     results.append(
#                         TestResult(
#                             planned_test=planned,
#                             payload=payload,
#                             success=success,
#                             evidence=evidence,
#                         )
#                     )

#                 except PlaywrightTimeoutError as e:
#                     results.append(
#                         TestResult(
#                             planned_test=planned,
#                             payload=payload,
#                             success=False,
#                             evidence="Timeout when loading page or submitting form.",
#                             error=str(e),
#                         )
#                     )
#                 except Exception as e:
#                     results.append(
#                         TestResult(
#                             planned_test=planned,
#                             payload=payload,
#                             success=False,
#                             evidence="Exception during XSS test execution.",
#                             error=str(e),
#                         )
#                     )

#             browser.close()

#         return results

#     # ---------------------------
#     # 内部辅助方法
#     # ---------------------------

#     def _submit_form(self, page) -> None:
#         """
#         尝试以比较通用的方式提交当前页面上的表单。
#         这是一个简化版实现，后续可以针对 Juice Shop 进一步优化：
#           - 找最近的 <button type=submit>
#           - 或者模拟按 Enter 键
#         """
#         # 先尝试点击 type=submit 的按钮
#         btn = page.query_selector("button[type=submit], input[type=submit]")
#         if btn:
#             btn.click()
#             return

#         # 找不到 submit 按钮，尝试按 Enter 提交
#         try:
#             page.keyboard.press("Enter")
#         except Exception:
#             # 最后啥也不做，由上层逻辑继续
#             pass