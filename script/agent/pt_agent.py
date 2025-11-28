# script/agent/pt_agent.py

# from script.scanner.web_attack_surface_scanner import WebAttackSurfaceScanner
# from script.scanner.attack_surface_view import build_llm_attack_surface_view
# from script.analysis.owasp_llm_analyzer import OwaspTop10LLMAnalyzer
# from script.payload.payload_registry import PayloadTemplateRegistry
# from script.executor import (
#     ExecutorRegistry,
#     XssAttackExecutor,
#     TestContext,
#     PlannedTest,
# )
import os
# from script.executor.test_executor import TestExecutor  # 以后再写

from script.scanner.site_scanner import SiteScanner
from script.scanner.dom_distiller import InteractionDomDistiller

class PTAgent:
    def __init__(self, base_url: str, llm_client):
        self.base_url = base_url
        # self.scanner = WebAttackSurfaceScanner(
        #     base_url=base_url,
        #     max_depth=3,
        #     headless=True,
        #     same_origin_only=True,
        # )
        self.scanner = SiteScanner(
            base_url=base_url,
            max_depth=2,  # 可以先从 1 或 2 开始试
            headless=True,
            same_origin_only=True,
        )
        self.llm_analyzer = None # OwaspTop10LLMAnalyzer(llm_client)
        # self.executor = TestExecutor(...)

    def run(self):
        # Step 1: 感知 → 扫描整个站点，得到 SiteAsset
        site_asset = self.scanner.scan()

        print("\n=== Site scan finished ===")
        print(f"Base URL: {site_asset.base_url}")
        print(f"Total pages: {len(site_asset.pages)}\n")

        for url, page in site_asset.pages.items():
            print(f"- Page: {url}")
            print(f"  title: {page.title}")
            print(f"  inputs: {len(page.inputs)}")
            print(f"  clickables: {len(page.clickables)}")
            print(f"  scripts: {len(page.scripts)}")
            print(f"  api_calls: {len(page.api_calls)}")

            distiller = InteractionDomDistiller()
            dsl = distiller.distill_html(page.html)

            print("=== Distilled DSL ===")
            print(dsl)

            print()

    # def run(self):
    #     # Step 1: 感知 → 扫描攻击面
    #     surface = self.scanner.scan()
    #
    #     # Step 2: 思考 → LLM 分析攻击面，找出“疑似漏洞点”
    #     view = build_llm_attack_surface_view(surface)
    #     analysis_result = self.llm_analyzer.analyze(view)
    #
    #     # Step 3: 规划测试（现在可以先只打印，之后再接 TestExecutor）
    #     print("\n=== Potential issues suggested by LLM ===\n")
    #
    #     for issue in analysis_result.issues:
    #         print(f"- {issue.location} [{issue.owasp_category}]")
    #         print(f"  Reason: {issue.risk_reason}")
    #
    #         # 打印关联的 ID（如果有）
    #         if issue.related_input_id is not None:
    #             print(f"  related_input_id: {issue.related_input_id}")
    #
    #         if issue.related_endpoint_id is not None:
    #             print(f"  related_endpoint_id: {issue.related_endpoint_id}")
    #
    #         # 测试思路
    #         for t in issue.suggested_tests:
    #             print(f"  * Test idea: {t}")
    #
    #         print()
    #
    #     # -----------------------------
    #     # Step 4.1: 加载 Payload 模版（注意：已经在 for 外面了！）
    #     # -----------------------------
    #     registry = PayloadTemplateRegistry()
    #     agent_dir = os.path.dirname(os.path.abspath(__file__))
    #     project_root = os.path.dirname(agent_dir)
    #     templates_dir = os.path.join(project_root, "payload", "templates")
    #     registry.load_from_directory(templates_dir)
    #
    #     print("\n=== Loaded Payload Templates ===")
    #     for vt in registry.list_vuln_types():
    #         tmpls = registry.get_templates_for_vuln(vt)
    #         print(f"VulnType: {vt}, Count: {len(tmpls)}")
    #
    #     # -----------------------------
    #     # Step 4.2: 创建并注册 XSS 执行器
    #     # -----------------------------
    #     executor_registry = ExecutorRegistry()
    #     xss_executor = XssAttackExecutor(headless=True)
    #     executor_registry.register(xss_executor, ["xss"])
    #
    #     # 先简单拿一组 XSS 模版（第一轮只用一个）
    #     xss_templates = registry.get_by_category("xss")
    #     if not xss_templates:
    #         print("\n[WARN] No XSS templates loaded, skip XSS PoC.\n")
    #         return
    #
    #     xss_template = xss_templates[0]  # PoC: 先用第一个模板
    #
    #     # -----------------------------
    #     # Step 4.3: 针对 XSS 相关的 issue 做 PoC
    #     # -----------------------------
    #     print("\n=== Running XSS PoC tests (only A03 + related_input_id issues) ===\n")
    #
    #     xss_exec = executor_registry.get_executor_for("xss")
    #     if xss_exec is None:
    #         print("[ERROR] No executor registered for vuln_type='xss'")
    #         return
    #
    #     for issue in analysis_result.issues:
    #         # 简单过滤：只挑 A03: Injection 且有 related_input_id 的
    #         if not issue.owasp_category.startswith("A03"):
    #             continue
    #         if issue.related_input_id is None:
    #             continue
    #
    #         # 根据 related_input_id 找回原来的 InputField
    #         input_field = None
    #         for f in surface.inputs:
    #             # 假设你在 InputField 里已经加了 id:int 字段
    #             if getattr(f, "id", None) == issue.related_input_id:
    #                 input_field = f
    #                 break
    #
    #         if input_field is None:
    #             print(f"[WARN] InputField with id={issue.related_input_id} not found, skip issue {issue.location}")
    #             continue
    #
    #         print(f"\n>>> XSS PoC for issue: {issue.location} (input id={issue.related_input_id})")
    #
    #         # 构造测试上下文
    #         context = TestContext(
    #             base_url=self.base_url,
    #             surface=surface,
    #             issue=issue,
    #             input_field=input_field,
    #         )
    #
    #         # 构造一个 PlannedTest（这里只做一轮 PoC，round_index=1）
    #         planned = PlannedTest(
    #             vuln_type="xss",
    #             template_id=xss_template.id,
    #             round_index=1,
    #             note="PoC: basic stored XSS check",
    #         )
    #
    #         # 执行模板（可能对同一模板里的多个 payload 逐个尝试）
    #         results = xss_exec.execute(context, planned, xss_template)
    #
    #         # 简单把结果打印出来
    #         for res in results:
    #             status = "POSSIBLE XSS!" if res.success else "no signal"
    #             print(f"  - payload: {repr(res.payload)} -> {status}")
    #             print(f"    evidence: {res.evidence}")
    #             if res.error:
    #                 print(f"    error: {res.error}")