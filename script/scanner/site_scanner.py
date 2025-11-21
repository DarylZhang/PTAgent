# script/scanner/site_scanner.py

from __future__ import annotations

from typing import Dict, Set, List
from urllib.parse import urlparse, urljoin

from playwright.sync_api import sync_playwright, Page, Request

from .page_asset import (
    SiteAsset,
    PageAsset,
    ScriptAsset,
    ApiCall,
    InputField,
    ClickableElement,
)


class SiteScanner:
    """
    站点级扫描器：
      - 从 base_url 出发，递归地爬取页面（有限深度）
      - 对每个页面构建一个 PageAsset
      - 最终返回一个 SiteAsset（相当于新 AttackSurface）

    注意：
      - 这里把「页面」理解为完整 URL，包括 hash（#/login）；
        也就是说 http://host/#/login 和 http://host/#/contact 会被视为两个 PageAsset。
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = 2,
        headless: bool = True,
        same_origin_only: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.headless = headless
        self.same_origin_only = same_origin_only

        parsed = urlparse(self.base_url)
        self._base_origin = (parsed.scheme, parsed.netloc)

        # 站点资产
        self._site_asset = SiteAsset(base_url=self.base_url)

        # 已访问 URL 集合（包含 hash）
        self._visited: Set[str] = set()

        # 各种 ID 计数器（全局递增，方便 LLM 关联）
        self._next_input_id = 1
        self._next_clickable_id = 1
        self._next_api_id = 1
        self._next_submission_id = 1  # 预留，将来用

    # ==============================
    # 对外入口：扫描整个站点
    # ==============================
    def scan(self) -> SiteAsset:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context()

            # 在 context 层面收集 API 调用，并根据当前页面 URL 归属
            self._api_calls_buffer: Dict[str, List[ApiCall]] = {}

            def on_request_finished(req: Request) -> None:
                try:
                    rt = req.resource_type
                    if rt not in ("xhr", "fetch"):
                        return

                    frame_url = req.frame.url

                    # 有些请求类型上调用 post_data() 会抛异常，这里包一层
                    try:
                        body = req.post_data()
                    except Exception:
                        body = None

                    api = ApiCall(
                        id=self._next_api_id,
                        url=req.url,
                        method=req.method,
                        resource_type=rt,
                        request_body=body,
                        page_url=frame_url,
                    )
                    self._next_api_id += 1

                    bucket = self._api_calls_buffer.setdefault(frame_url, [])
                    bucket.append(api)

                except Exception as e:
                    # 不要让监听器异常中断整个扫描，最多打印一行日志
                    print(f"[WARN] on_request_finished error for {req.url}: {e}")

            context.on("requestfinished", on_request_finished)

            page = context.new_page()

            # 从 base_url 开始爬
            self._crawl_page(page, self.base_url, depth=0)

            browser.close()

        return self._site_asset

    # ==============================
    # 内部：递归爬取页面
    # ==============================
    def _crawl_page(self, page: Page, url: str, depth: int) -> None:
        if depth > self.max_depth:
            return
        if url in self._visited:
            return
        if not self._should_visit(url):
            return

        self._visited.add(url)

        try:
            page.goto(url, wait_until="networkidle", timeout=15000)
        except Exception as e:
            print(f"[WARN] Failed to load {url}: {e}")
            return

        current_url = page.url  # 可能存在重定向
        title = page.title()
        html = page.content()

        dom_snapshot = None
        body = page.query_selector("body")
        if body:
            dom_html = body.inner_html()
            if len(dom_html) > 20000:
                dom_html = dom_html[:20000] + "\n<!-- truncated -->"
            dom_snapshot = dom_html

        # 1) 收集脚本
        scripts = self._extract_scripts(page)

        # 2) 收集输入框
        inputs = self._extract_inputs(page, current_url)

        # 3) 收集可点击元素
        clickables = self._extract_clickables(page, current_url)

        # 4) 收集在这个页面生命周期中发生的 API 调用
        #    简化版：目前直接从全局 buffer 里拿全部（以后可以按 page_url 精细区分）。
        api_calls: List[ApiCall] = []
        global_apis = self._api_calls_buffer.get("_global", [])
        # 注意：这里没有做页面粒度划分，只是让 PageAsset 至少有 API 信息可用。
        api_calls.extend(global_apis)

        # 5) 目前 submissions 先留空，以后通过点击行为 + 网络差分来填
        submissions = []

        # 构建 PageAsset
        pa = PageAsset(
            url=url,
            final_url=current_url,
            title=title,
            html=html,
            dom_snapshot=dom_snapshot,
            scripts=scripts,
            inputs=inputs,
            clickables=clickables,
            api_calls=api_calls,
            submissions=submissions,
        )

        self._site_asset.pages[url] = pa

        # 6) 找出本页中的下一层链接，继续爬
        links = self._collect_links(page, current_url)
        for link in links:
            self._crawl_page(page, link, depth + 1)

    # ==============================
    # URL 访问控制
    # ==============================
    def _should_visit(self, url: str) -> bool:
        parsed = urlparse(url)

        # 只处理 http/https
        if parsed.scheme not in ("http", "https"):
            return False

        if self.same_origin_only:
            if (parsed.scheme, parsed.netloc) != self._base_origin:
                return False

        return True

    def _collect_links(self, page: Page, current_url: str) -> List[str]:
        links: List[str] = []

        anchors = page.query_selector_all("a[href]")
        for a in anchors:
            href = a.get_attribute("href")
            if not href:
                continue

            # 解析 hash-only 链接 (#/login) 或相对路径
            absolute_url = urljoin(current_url, href)

            if self._should_visit(absolute_url):
                links.append(absolute_url)

        # 去重
        unique_links: List[str] = []
        seen: Set[str] = set()
        for link in links:
            if link not in seen:
                seen.add(link)
                unique_links.append(link)

        return unique_links

    # ==============================
    # 脚本收集
    # ==============================
    def _extract_scripts(self, page: Page) -> List[ScriptAsset]:
        scripts: List[ScriptAsset] = []

        # 外链脚本
        for el in page.query_selector_all("script[src]"):
            src = el.get_attribute("src")
            script_type = el.get_attribute("type")
            scripts.append(
                ScriptAsset(
                    src=src,
                    inline_code=None,
                    script_type=script_type,
                    is_inline=False,
                )
            )

        # 内联脚本
        for el in page.query_selector_all("script:not([src])"):
            code = el.inner_html()
            if code and len(code) > 5000:
                code = code[:5000] + "\n/* truncated */"
            script_type = el.get_attribute("type")
            scripts.append(
                ScriptAsset(
                    src=None,
                    inline_code=code,
                    script_type=script_type,
                    is_inline=True,
                )
            )

        return scripts

    # ==============================
    # 输入控件收集
    # ==============================
    def _extract_inputs(self, page: Page, page_url: str) -> List[InputField]:
        inputs: List[InputField] = []

        elements = page.query_selector_all("input, textarea, select")
        for el in elements:
            tag = el.evaluate("e => e.tagName.toLowerCase()")
            dom_id = el.get_attribute("id")
            name = el.get_attribute("name")
            input_type = el.get_attribute("type")
            placeholder = el.get_attribute("placeholder")

            css_selector = self._build_css_selector(tag, dom_id, name)

            field = InputField(
                internal_id=self._next_input_id,
                page_url=page_url,
                tag=tag,
                name=name,
                input_type=input_type,
                dom_id=dom_id,
                placeholder=placeholder,
                css_selector=css_selector,
            )
            self._next_input_id += 1
            inputs.append(field)

        return inputs

    # ==============================
    # 可点击元素收集
    # ==============================
    def _extract_clickables(self, page: Page, page_url: str) -> List[ClickableElement]:
        clickables: List[ClickableElement] = []

        elements = page.query_selector_all("button, a, [role=button], input[type=submit]")
        for el in elements:
            tag = el.evaluate("e => e.tagName.toLowerCase()")
            dom_id = el.get_attribute("id")
            role = el.get_attribute("role")
            text = el.inner_text().strip() if el.inner_text() else None
            disabled_attr = el.get_attribute("disabled")
            disabled = disabled_attr is not None
            onclick = el.get_attribute("onclick")

            css_selector = self._build_css_selector(tag, dom_id, None)

            ce = ClickableElement(
                internal_id=self._next_clickable_id,
                page_url=page_url,
                tag=tag,
                css_selector=css_selector,
                text=text,
                disabled=disabled,
                role=role,
                onclick=onclick,
            )
            self._next_clickable_id += 1
            clickables.append(ce)

        return clickables

    # ==============================
    # 辅助：构造简单 CSS selector
    # ==============================
    @staticmethod
    def _build_css_selector(tag: str, dom_id: str | None, name: str | None) -> str:
        if dom_id:
            return f"{tag}#{dom_id}"
        if name:
            return f'{tag}[name="{name}"]'
        return tag