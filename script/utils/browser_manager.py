import asyncio
import random
import logging
from playwright.async_api import async_playwright, Page, BrowserContext

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RequestEngine")


class BrowserManager:
    def __init__(self, headless=False):
        self.headless = headless
        self.playwright = None
        self.browser = None
        self.context = None

    async def initialize(self):
        """启动浏览器和上下文"""
        self.playwright = await async_playwright().start()
        # 这里可以加 args=['--no-sandbox'] 等配置
        self.browser = await self.playwright.chromium.launch(headless=self.headless)

        # 创建统一上下文（这里可以统一设置 UserAgent, Permissions 等）
        self.context = await self.browser.new_context(
            user_agent="PTAgent/1.0 (Automated Pentest Research)",
            ignore_https_errors=True
        )
        logger.info("BrowserManager initialized successfully.")

    async def navigate(self, url: str) -> Page:
        """统一的访问入口，包含随机等待"""
        # 模拟随机等待，避免被识别为机器人
        await asyncio.sleep(2)

        page = await self.context.new_page()
        try:
            await page.goto(url, wait_until="networkidle")
            return page
        except Exception as e:
            logger.error(f"Navigation failed: {e}")
            await page.close()
            raise e

    async def close(self):
        """资源清理"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        logger.info("BrowserManager closed.")

    async def _wait_strategy(self):
        """
        统一的等待策略
        不要使用固定的 sleep，使用随机抖动 (Jitter) 来模拟人类行为
        """
        # 比如：在 2 到 5 秒之间随机等待
        sleep_time = random.uniform(2.0, 5.0)
        logger.info(f"Cooling down for {sleep_time:.2f} seconds...")
        await asyncio.sleep(sleep_time)

    async def execute_action(self, page: Page, action_callback):
        """
        统一执行动作的包装器（例如点击、输入）
        可以在这里再次插入等待，或者截图记录
        """
        await self._wait_strategy()
        result = await action_callback(page)
        return result