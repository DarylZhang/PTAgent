# script/agent/auth_agent.py

import threading
import time
import queue
from typing import Optional, Dict
from playwright.sync_api import sync_playwright
from scanner.page_asset import AuthCredentials  # 假设之前定义的 AuthCredentials 在这里


class AuthAgent(threading.Thread):
    def __init__(self, headless: bool = True):
        super().__init__()
        self.headless = headless
        self.daemon = True  # 设置为守护线程，主程序退出时它也会退出

        # 任务队列：存放 (url, type) -> type: 'login' | 'register'
        self.task_queue = queue.Queue()

        # 结果容器
        self.credentials: Optional[AuthCredentials] = None
        self.found_login_url: Optional[str] = None
        self.found_register_url: Optional[str] = None

        # 状态标志
        self.finished = False
        self.is_running = True

    def add_task(self, url: str, page_type: str):
        """
        Scanner 调用的入口，投喂 URL
        """
        if self.credentials:
            return  # 已经拿到凭证了，不需要再加任务

        if page_type == 'login' and not self.found_login_url:
            self.found_login_url = url
            self.task_queue.put(('login', url))
        elif page_type == 'register' and not self.found_register_url:
            self.found_register_url = url
            # 注册页优先级更高，放在队列前面？Queue 不支持插队，但我们可以逻辑处理
            # 简单起见，先放入，run 里会判断
            self.task_queue.put(('register', url))

    def run(self):
        """
        线程主循环
        """
        print("[AuthAgent] Thread started, waiting for tasks...")

        while self.is_running and not self.credentials:
            try:
                # 阻塞等待任务，每 2 秒检查一次 is_running
                task_type, url = self.task_queue.get(timeout=2)
            except queue.Empty:
                continue

            print(f"[AuthAgent] Processing {task_type} task: {url}")

            # 这里调用实际的 LLM 注册/登录逻辑
            # 注意：为了线程安全，这里启动独立的 playwright
            self._execute_auth_logic(url, task_type)

            self.task_queue.task_done()

        self.finished = True
        print("[AuthAgent] Thread finished.")

    def _execute_auth_logic(self, url: str, task_type: str):
        """
        这里是集成 LLM 的核心地方
        """
        # 如果已经有凭证，直接跳过
        if self.credentials: return

        # 模拟逻辑：如果遇到注册页，先注册，再登录
        # 实际代码中，这里会调用你的 LLM Agent
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                context = browser.new_context()
                page = context.new_page()

                # TODO: 这里替换为你真实的 LLM 交互逻辑
                # page.goto(url)
                # llm_action = utils.plan(page_content)
                # ...

                # 假设我们在这里成功获取了凭证
                # self.credentials = AuthCredentials(...)

                browser.close()
        except Exception as e:
            print(f"[AuthAgent] Error processing {url}: {e}")

    def stop(self):
        self.is_running = False

    def get_credentials(self, timeout: int = 60) -> Optional[AuthCredentials]:
        """
        Scanner 结束时调用此方法等待结果
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.credentials:
                return self.credentials
            time.sleep(1)
        return None