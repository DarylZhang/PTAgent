import sys
import os

# 确保能找到 script 模块
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from script.llm_service import LLMService
from script.static_analyzer import StaticAnalyzer
from script.dynamic_analyzer import DynamicAnalyzer


def main():
    target_url = "https://demo.owasp-juice.shop"  # 或者任何你想测试的站

    print("=== PhD Hybrid Vulnerability Scanner Framework ===")

    # 1. 初始化服务
    llm = LLMService(use_mock=True)  # 使用 Mock 模式，确保你可以直接跑通
    static_engine = StaticAnalyzer(llm)
    dynamic_engine = DynamicAnalyzer(llm)

    try:
        # 2. 动态引擎启动 (Phase 1: Recon)
        print("\n[Phase 1] Launching Browser for Recon...")
        page = dynamic_engine.start_session(target_url)

        # 3. 提取静态资源 (Extract Assets)
        # 获取页面所有加载的 Script 标签内容
        # 这里为了演示，我们假设抓到了一个包含 API 调用的 JS 片段
        # 实际项目中，你需要遍历 page.evaluate("performance.getEntries()") 来下载真实 JS
        mock_js_assets = [
            """
            function login() {
                var u = document.getElementById('user').value;
                fetch('/api/Users/login', {
                    method: 'POST',
                    body: JSON.stringify({email: u, password: '123'})
                });
            }
            """
        ]

        # 4. 静态分析 (Phase 2: Static Analysis)
        print("\n[Phase 2] Running Static Analysis on JS Assets...")
        static_endpoints = static_engine.run(mock_js_assets)
        print(f" -> Found {len(static_endpoints)} endpoints via Static Analysis.")
        for ep in static_endpoints:
            print(f"    - [{ep.method}] {ep.url} (Source: {ep.source})")

        # 5. 动态交互 (Phase 3: Dynamic Exploration)
        print("\n[Phase 3] Running Agent Exploration...")
        dynamic_engine.execute_agent_loop(page)

        # 6. 获取所有动态捕获的流量
        dynamic_endpoints = dynamic_engine.sync_traffic(page)
        print(f" -> Captured {len(dynamic_endpoints)} endpoints via Dynamic Traffic Hook.")

        # 7. 攻击验证 (Phase 4: Weaponization)
        # 合并目标队列
        all_targets = static_endpoints + dynamic_endpoints
        print(f"\n[Phase 4] Attacking {len(all_targets)} Targets...")

        for target in all_targets:
            payloads = llm.generate_payloads(target)
            dynamic_engine.verify_vulnerability(page, target, payloads)

    finally:
        dynamic_engine.close()
        print("\n=== Scan Finished ===")


if __name__ == "__main__":
    main()