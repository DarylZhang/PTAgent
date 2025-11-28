import time
from playwright.sync_api import sync_playwright, Page
from script.datatypes import Endpoint, Action
from script.llm_service import LLMService


class DynamicAnalyzer:
    def __init__(self, llm: LLMService):
        self.llm = llm
        self.playwright = None
        self.browser = None
        # 存储拦截到的请求
        self.captured_traffic = []

    def start_session(self, target_url: str):
        self.playwright = sync_playwright().start()
        # headless=False 方便你看到浏览器的操作，调试时设为 True
        self.browser = self.playwright.chromium.launch(headless=False)
        context = self.browser.new_context()
        page = context.new_page()

        # --- 核心创新：注入流量监控 Hook ---
        # 这段 JS 会在页面所有脚本执行前运行
        monitor_script = """
        window.captured_requests = [];

        // Hook fetch
        const originalFetch = window.fetch;
        window.fetch = async (...args) => {
            const [resource, config] = args;
            window.captured_requests.push({
                type: 'fetch',
                url: resource instanceof Request ? resource.url : resource,
                method: config?.method || 'GET',
                body: config?.body
            });
            return originalFetch(...args);
        };

        // Hook XHR
        const originalOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
            this.addEventListener('load', function() {
                window.captured_requests.push({
                    type: 'xhr',
                    url: url,
                    method: method
                });
            });
            return originalOpen.apply(this, arguments);
        };
        """
        page.add_init_script(monitor_script)

        print(f"[*] Navigating to {target_url}...")
        page.goto(target_url)
        try:
            page.wait_for_load_state("networkidle", timeout=5000)
        except:
            pass

        return page

    def sync_traffic(self, page: Page) -> list[Endpoint]:
        """
        从浏览器内存中把 Hook 到的数据拉回到 Python
        """
        raw_data = page.evaluate("window.captured_requests")
        new_endpoints = []

        # 简单的去重逻辑
        current_urls = [t['url'] for t in self.captured_traffic]

        for req in raw_data:
            if req['url'] not in current_urls:
                ep = Endpoint(
                    url=req['url'],
                    method=req.get('method', 'GET'),
                    source="dynamic_traffic_hook",
                    context=f"Body: {req.get('body')}"
                )
                new_endpoints.append(ep)
                self.captured_traffic.append(req)

        return new_endpoints

    def execute_agent_loop(self, page: Page, max_steps=3):
        """
        简单的 Agent 循环：看页面 -> 决定操作 -> 执行
        """
        print("[*] Starting Agent Exploration Loop...")
        for i in range(max_steps):
            # 1. 简单的 DOM 概览 (这里简化处理，实际用 Clean HTML)
            dom_preview = page.content()[:1000] + "..."

            # 2. LLM 决策
            action = self.llm.decide_next_action(dom_preview)
            print(f"   [Step {i + 1}] Agent decided: {action.type} -> {action.reasoning}")

            if action.type == "stop":
                break
            elif action.type == "click" and action.selector:
                try:
                    # 尝试点击，如果 selector 不存在可能会报错，这里做个简单捕获
                    if page.locator(action.selector).count() > 0:
                        page.click(action.selector)
                        page.wait_for_timeout(1000)  # 等待反应
                except:
                    pass

            # 每次操作后，看看有没有新的流量产生
            new_eps = self.sync_traffic(page)
            if new_eps:
                print(f"      -> Triggered {len(new_eps)} new requests!")

    def verify_vulnerability(self, page: Page, endpoint: Endpoint, payloads: list[str]):
        """
        武器化验证
        """
        print(f"   [!] Testing {endpoint.url} with {len(payloads)} payloads...")
        # 这里仅做演示 Log，实际需要用 page.request.post() 发包
        for p in payloads:
            # page.goto(endpoint.url + "?q=" + p)
            pass

    def close(self):
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()