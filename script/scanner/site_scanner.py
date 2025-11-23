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
        
        # 当前页面加载期间捕获的 API
        self._captured_apis: List[ApiCall] = []

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
                    if rt not in ("xhr", "fetch", "websocket"):
                        return

                    frame_url = req.frame.url

                    # 有些请求类型上调用 post_data() 会抛异常，这里包一层
                    try:
                        body = req.post_data()
                    except Exception:
                        body = None

                    # 尝试获取响应信息
                    resp = req.response()
                    resp_status = None
                    resp_headers = {}
                    resp_body = None
                    
                    if resp:
                        resp_status = resp.status
                        resp_headers = resp.all_headers()
                        try:
                            # 限制响应体大小，避免过大
                            body_bytes = resp.body()
                            if len(body_bytes) > 10000:
                                resp_body = body_bytes[:10000].decode("utf-8", errors="replace") + "\n<!-- truncated -->"
                            else:
                                resp_body = body_bytes.decode("utf-8", errors="replace")
                        except Exception:
                            pass

                    api = ApiCall(
                        id=self._next_api_id,
                        url=req.url,
                        method=req.method,
                        resource_type=rt,
                        request_body=body,
                        page_url=frame_url,
                        request_headers=req.all_headers(),
                        # request.headers_array() 包含 cookies，或者单独解析
                        # 这里简单处理，暂不单独解析 cookies 结构，后续可增强
                        response_status=resp_status,
                        response_headers=resp_headers,
                        response_body=resp_body,
                    )
                    self._next_api_id += 1
                    
                    # 存入当前页面的捕获列表
                    self._captured_apis.append(api)

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
            # 清空上一页的捕获记录
            self._captured_apis.clear()
            page.goto(url, wait_until="networkidle", timeout=15000)
            # 等待 2 秒，确保 SPA 的后续请求（如 socket 连接、延迟加载）能被捕获
            page.wait_for_timeout(2000)
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
        #    使用 _captured_apis (在 goto 前已清空)
        api_calls: List[ApiCall] = self._captured_apis[:]

        # 5) 构建 SubmissionUnit
        #    逻辑：遍历本页触发的所有 API Call，尝试寻找“相关”的 InputField
        submissions: List[SubmissionUnit] = []
        
        # 简单的启发式映射：
        # 如果 API 请求体/参数里出现了 input 的 name/id，就认为它们相关
        from .page_asset import SubmissionUnit

        for api in api_calls:
            related_inputs = []
            # 提取 API 参数特征（简单处理：全转字符串搜）
            # 以后可以解析 JSON / Form Data 做精确匹配
            api_payload_str = ""
            if api.request_body:
                api_payload_str += str(api.request_body)
            if api.url:
                api_payload_str += api.url  # 包含 query params

            for inp in inputs:
                # 如果 input 有 name，且 name 出现在 API 参数里
                if inp.name and inp.name in api_payload_str:
                    related_inputs.append(inp.internal_id)
                # 或者如果 input 有 id，且 id 出现在 API 参数里
                elif inp.dom_id and inp.dom_id in api_payload_str:
                    related_inputs.append(inp.internal_id)
            
            # 如果没找到明确关联，但 API 是 POST/PUT，且页面有输入框，
            # 可能是“整个表单”提交，把所有输入框都关联上去（宁滥勿缺，交给 LLM 甄别）
            if not related_inputs and api.method in ("POST", "PUT", "PATCH") and inputs:
                related_inputs = [i.internal_id for i in inputs]

            # 创建 SubmissionUnit
            # 这里的 trigger_clickable_id 很难在被动扫描中确定，暂时留空或填 None
            su = SubmissionUnit(
                id=self._next_submission_id,
                page_url=url,
                trigger_clickable_id=None,
                related_input_ids=related_inputs,
                api_call_ids=[api.id],
                kind="auto_detected",
            )
            self._next_submission_id += 1
            submissions.append(su)

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