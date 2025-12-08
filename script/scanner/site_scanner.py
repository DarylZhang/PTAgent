# script/scanner/site_scanner.py

from __future__ import annotations

from typing import Dict, Set, List, Optional, Any
from urllib.parse import urlparse, urljoin
import json
from .page_asset import SubmissionUnit
from urllib.parse import parse_qs
from scanner.utils.html_cleaner import clean_html_for_llm
from .link_extractor import JsLinkExtractor
from .page_asset import (
    SiteAsset,
    PageAsset,
    ScriptAsset,
    ApiCall,
    InputField,
    ClickableElement,
    Cookie,
    StorageItem, AuthCredentials,
)
from playwright.sync_api import sync_playwright, Page, Request, Browser, BrowserContext, Playwright # <-- 新增导入 Browser, BrowserContext, Playwright

class SiteScanner:

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

        # 站点资产 (保持不变)
        self._site_asset = SiteAsset(base_url=self.base_url)
        self._visited: Set[str] = set()
        self._next_input_id = 1
        self._next_clickable_id = 1
        self._next_api_id = 1
        self._next_submission_id = 1
        self._captured_apis: List[ApiCall] = []
        self._processed_script_urls: Set[str] = set()
        self._auth_headers = {}

        # --- Playwright 核心对象初始化 ---
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None  # 供扫描和攻击使用的持久化 Page

        # 启动 Playwright 资源，确保 self._page 存在
        self._initialize_playwright()

        # 在 Context 层面收集 API 调用，并根据当前页面 URL 归属 (初始化)
        self._api_calls_buffer: Dict[str, List[ApiCall]] = {}

        # 绑定监听器到 Context
        if self._context:
            self._context.on("requestfinished", self._on_request_finished_wrapper)

    # ==============================
    # Playwright 资源管理
    # ==============================
    def _initialize_playwright(self):
        """
        初始化 Playwright 实例、浏览器和 Page 对象。
        """
        print("[*] Launching Headless Browser...")

        # 1. 启动 Playwright
        self._playwright = sync_playwright().start()

        # 2. 启动 Browser 实例
        self._browser = self._playwright.chromium.launch(
            headless=self.headless,
            args=["--ignore-certificate-errors"]
        )

        # 3. 创建 Browser Context
        self._context = self._browser.new_context(
            user_agent="PTAgent/1.0 (Automated Pentest Research)",
            ignore_https_errors=True
        )

        # 4. 创建 Page 实例
        self._page = self._context.new_page()

    def close(self):
        """
        显式关闭 Playwright 资源，在 PTAgent 退出时调用。
        """
        if self._browser:
            print("[*] Closing Browser...")
            self._browser.close()
        if self._playwright:
            self._playwright.stop()

    # # 可以使用 __del__ 确保资源被释放
    # def __del__(self):
    #     self.close()

    # ==============================
    # 对外入口：扫描整个站点
    # ==============================
    def scan(self) -> SiteAsset:
        # **重要修正：移除 Playwright 局部初始化块**

        # 确保 Page 存在
        if not self._page:
            print("[ERROR] Browser page not initialized. Re-running initialization.")
            self._initialize_playwright()
            if not self._page:
                raise RuntimeError("Failed to initialize Playwright resources.")

        try:
            # 清空之前的 API 捕获 buffer
            self._api_calls_buffer = {}

            # 从 base_url 开始爬
            self._crawl_page(self._page, self.base_url, depth=0)  # <-- 使用 self._page

        except Exception as e:
            print(f"[FATAL] Scan failed: {e}")

        finally:
            # 扫描主循环结束，不需要在这里关闭浏览器，因为它要留给攻击阶段用
            pass

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

        # -------------------------------------------------
        # [Step 1] 探测阶段：判断是 API 还是 页面
        # -------------------------------------------------
        is_api = False
        try:
            # 使用 APIRequest (只发包不渲染)
            probe_resp = page.request.get(url, timeout=5000)
            status_code = probe_resp.status
            content_type = probe_resp.headers.get("content-type", "").lower()

            # [新增逻辑 A]：捕获 HTTP 鉴权状态码
            # 如果是 401 或 403，说明这是个受保护资源
            if status_code in (401, 403):
                print(f"[INFO] Found auth-protected resource: {url} ({status_code})")
                self._site_asset.auth_required_urls.add(url)

                # 依然把它当做 API 记录下来 (作为备忘)，但不去渲染它
                self._record_standalone_api(url, probe_resp)
                return

            # 读取 Body 文本（注意：body() 返回 bytes，我们需要 decode）
            # 为了效率，我们不需要 decode 全部，只需要前 1KB 也就够判断了
            # 但为了准确的 JSON 解析，取稍微多一点也没事
            try:
                body_bytes = probe_resp.body()
                # 简单 decode，忽略错误
                body_str = body_bytes.decode("utf-8", errors="ignore").strip()
            except:
                body_str = ""

            # ==================================================
            # 逻辑 A: 状态码特征 (Status Code) - 你同意的部分
            # ==================================================
            # 401/403: 需要鉴权
            # 405: 方法不允许 (如 GET 不行，可能是 POST 接口)
            # 204: No Content (通常是 API)
            if status_code in (401, 403, 405, 204):
                is_api = True

            # ==================================================
            # 逻辑 B: Content-Type 强特征
            # ==================================================
            elif "application/json" in content_type or \
                    "application/xml" in content_type or \
                    "text/xml" in content_type:
                is_api = True

            # ==================================================
            # 逻辑 C: 内容嗅探 (Content Sniffing) - 解决 URL 命名不规范问题
            # ==================================================
            elif body_str:
                # 1. 伪装成 HTML/Text 的 JSON
                # 如果内容以 { 或 [ 开头，且以 } 或 ] 结尾 (简单判断)
                if body_str.startswith("{") or body_str.startswith("["):
                    # 进一步确认：尝试简单的 json load 验证？或者直接这就够了
                    # 考虑到性能，直接以此判断通常足够准确
                    is_api = True

                # 2. HTML "完整性" 检查 (The "Skeleton" Test)
                # 如果 header 说是 html，但内容里完全没有 HTML 的骨架标签
                elif "text/html" in content_type:
                    lower_body = body_str.lower()[:500]  # 只看前 500 字符

                    # 定义网页的特征标签
                    has_doctype = "<!doctype" in lower_body
                    has_html_tag = "<html" in lower_body
                    has_head_tag = "<head" in lower_body

                    # 如果这些都没有，那它可能只是一个返回纯文本报错的接口
                    # 例如: "Error: User already exists"
                    if not (has_doctype or has_html_tag or has_head_tag):
                        # 这是一个 "非页面 HTML 响应" -> 归类为 API 资产
                        is_api = True

            # ==================================================
            # 决策执行
            # ==================================================
            if is_api:
                print(f"[INFO] Identified API endpoint (No Render): {url} [{status_code}]")
                self._record_standalone_api(url, probe_resp)
                return  # <--- 终止渲染

        except Exception as e:
            # 探测异常（网络超时等），保守策略：尝试去渲染
            print(f"[WARN] Probe failed for {url}: {e}")
            pass

        # -------------------------------------------------
        # [Step 2] 页面渲染阶段 (是 HTML，需要浏览器介入)
        # -------------------------------------------------
        try:
            # 清空上一页的捕获记录 (仅用于 page.goto 触发的被动流量)
            self._captured_apis.clear()

            response = page.goto(url, wait_until="networkidle", timeout=15000)
            if not response:  # 加载失败
                return

            # 二次确认：万一 probe 没拦住，page.goto 加载完发现还是 JSON (浏览器会在 pre 标签显示)
            # Playwright response 也有 headers
            ct = response.headers.get("content-type", "").lower()
            if "application/json" in ct:
                print(f"[INFO] Identified API after goto: {url}")
                # 这种情况下，虽然浪费了一次渲染，但还是应该记为 API
                # 由于 response 格式不一样，这里需要适配一下，或者直接忽略 DOM 解析
                # 简单起见，这里直接 return，防止 DOM 解析报错
                return

            page.wait_for_timeout(2000)

        except Exception as e:
            print(f"[WARN] Failed to load page {url}: {e}")
            return

        final_url = page.url
        # 如果发生了跨域跳转，且我们开启了同源限制
        if self.same_origin_only:
            # 复用 _should_visit 的逻辑来检查最终 URL
            if not self._should_visit(final_url):
                print(f"[WARN] Redirected to off-origin: {final_url}. Stopping analysis.")
                return

        current_url = page.url  # 可能存在重定向
        title = page.title()
        html = page.content()

        dom_snapshot = None
        body = page.query_selector("body")
        if body:
            dom_snapshot = body.inner_html()

        cleaned_html = clean_html_for_llm(html)

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
        


        for api in api_calls:
            related_inputs = []
            input_map = {} # param_name -> input_id

            # 尝试解析 Request Body (JSON or Form)
            params_found = set()
            
            # 1. 解析 JSON Body
            if api.request_body and api.request_body.startswith("{"):
                try:
                    json_body = json.loads(api.request_body)
                    if isinstance(json_body, dict):
                        params_found.update(json_body.keys())
                except:
                    pass
            
            # 2. 解析 Form Body (key=value)
            elif api.request_body and "=" in api.request_body:
                try:
                    qs = parse_qs(api.request_body)
                    params_found.update(qs.keys())
                except:
                    pass

            # 3. 解析 URL Query Params
            parsed_api = urlparse(api.url)
            if parsed_api.query:
                qs = parse_qs(parsed_api.query)
                params_found.update(qs.keys())

            # 核心匹配逻辑：
            # 遍历页面上的 Input，看它的 name 是否出现在 API 参数里
            for inp in inputs:
                if inp.name and inp.name in params_found:
                    related_inputs.append(inp.internal_id)
                    input_map[inp.name] = inp.internal_id
            
            # 如果没找到明确关联，但 API 是 POST/PUT，且页面有输入框，
            # 可能是“整个表单”提交，把所有输入框都关联上去（宁滥勿缺，交给 LLM 甄别）
            if not related_inputs and api.method in ("POST", "PUT", "PATCH") and inputs:
                related_inputs = [i.internal_id for i in inputs]
                # 这种情况下无法建立精确 map，只能留空

            # 创建 SubmissionUnit
            su = SubmissionUnit(
                id=self._next_submission_id,
                page_url=url,
                trigger_clickable_id=None,
                related_input_ids=related_inputs,
                input_map=input_map,
                api_call_ids=[api.id],
                kind="auto_detected",
            )
            self._next_submission_id += 1
            submissions.append(su)

        # 6) 收集 Cookies, Storage, Comments (OWASP Top 10)
        cookies_data, ls_data, ss_data = self._extract_storage(page)
        cookies = [Cookie(**c) for c in cookies_data]
        local_storage = [StorageItem(**i) for i in ls_data]
        session_storage = [StorageItem(**i) for i in ss_data]
        
        comments = self._extract_comments(page)
        
        meta = {}
        if response:
            try:
                meta["response_headers"] = response.all_headers()
                meta["status"] = response.status
            except Exception:
                pass

        # 构建 PageAsset
        pa = PageAsset(
            url=url,
            final_url=current_url,
            title=title,
            html=html,
            cleaned_html=cleaned_html,
            dom_snapshot=dom_snapshot,
            scripts=scripts,
            inputs=inputs,
            clickables=clickables,
            api_calls=api_calls,
            submissions=submissions,
            cookies=cookies,
            local_storage=local_storage,
            session_storage=session_storage,
            comments=comments,
            meta=meta,
        )

        self._site_asset.pages[url] = pa

        # 6) 找出本页中的下一层链接，继续爬
        links = self._collect_links(page, current_url, scripts)
        for link in links:
            self._crawl_page(page, link, depth + 1)

        # 在 SiteScanner 类中添加

    # ==============================
    # 授权扫描模式 (scan_authenticated)
    # ==============================
    def scan_authenticated(self, auth_creds: 'AuthCredentials') -> SiteAsset:
        """
        [第二阶段] 授权扫描模式
        使用提供的凭证，在已有的 Context 上重新扫描 site_asset.auth_required_urls 中的资源。
        """
        print(f"[*] Starting Authenticated Scan on {len(self._site_asset.auth_required_urls)} targets...")

        # **重要修正：不再创建新的 Playwright 实例**
        if not self._context or not self._page:
            raise RuntimeError("Browser context not available for authenticated scan.")

        # 1. 注入 Headers (直接调用 set_auth_context)
        # 注意：这里我们应该复用 set_auth_context 的逻辑，但为了避免重复打印，直接在 context 上操作
        if auth_creds.headers:
            self._context.set_extra_http_headers(auth_creds.headers)
            self._auth_headers.update(auth_creds.headers)

        # 2. 注入 Cookies
        if auth_creds.cookies:
            self._context.add_cookies(auth_creds.cookies)

        # 3. 注入 LocalStorage / SessionStorage (通过 Init Script)
        # 这是一个高级技巧：在页面任何 JS 执行之前，先由浏览器执行这段脚本
        init_js = ""

        if auth_creds.local_storage:
            print(f"  -> Injecting {len(auth_creds.local_storage)} items into LocalStorage.")
            for item in auth_creds.local_storage:
                # 使用 JSON.stringify (json.dumps) 处理 value，确保 value 中的引号、换行等特殊字符不会破坏 JS 语法
                k = json.dumps(item['key'])
                v = json.dumps(item['value'])
                # 构造 JS 语句： window.localStorage.setItem(key, value);
                init_js += f"window.localStorage.setItem({k}, {v});\n"

        if auth_creds.session_storage:
            print(f"  -> Injecting {len(auth_creds.session_storage)} items into SessionStorage.")
            for item in auth_creds.session_storage:
                k = json.dumps(item['key'])
                v = json.dumps(item['value'])
                # 构造 JS 语句： window.sessionStorage.setItem(key, value);
                init_js += f"window.sessionStorage.setItem({k}, {v});\n"

        if init_js:
            # 将生成的全部 JS 脚本添加到 Playwright Context
            self._context.add_init_script(init_js)

        # 4. 挂载 API 监听器 (保持不变，因为已经在 __init__ 中绑定到 self._context)
        self._api_calls_buffer = {}
        # 无需重新绑定，只需清空 buffer

        # 5. 遍历待扫队列
        targets = list(self._site_asset.auth_required_urls)

        for url in targets:
            print(f"[*] Re-scanning (Auth): {url}")
            if url in self._visited:
                self._visited.remove(url)

            # 使用 self._page 进行爬取
            self._crawl_page(self._page, url, depth=0)

            # --- 移除 browser.close() ---

        return self._site_asset

    # 为了复用，建议把之前 scan() 里的内部函数 on_request_finished 提取为类方法
    def _on_request_finished_wrapper(self, req: Request):
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

    def _record_standalone_api(self, url: str, response) -> None:
        """
        将主动发现的 API 端点记录到 SiteAsset 中。
        response: 是 APIResponse 对象 (来自 page.request.get)
        """
        try:
            # 尝试获取 Body (截断以防过大)
            body_bytes = response.body()
            if len(body_bytes) > 10000:
                resp_body = body_bytes[:10000].decode("utf-8", errors="replace") + "\n"
            else:
                resp_body = body_bytes.decode("utf-8", errors="replace")
        except:
            resp_body = None

        # 构造 ApiCall 对象
        api_entry = ApiCall(
            id=self._next_api_id,
            url=url,
            method="GET",  # 爬虫主动探测通常是 GET
            resource_type="fetch",  # 归类为 fetch
            request_body=None,
            page_url="crawler_discovery",  # 标记来源
            request_headers={},  # 主动请求的 headers 较难获取完全，留空或填默认
            response_status=response.status,
            response_headers=response.headers,
            response_body=resp_body
        )
        self._next_api_id += 1
        self._site_asset.discovered_apis.append(api_entry)

    def _collect_links(self, page: Page, current_url: str, scripts: List[ScriptAsset]) -> List[str]:
        """
        收集链接：
        1. DOM 中的 <a> 标签
        2. 扫描 JS (内联 + 下载外链) 中的 API 路径
        """
        found_links: Set[str] = set()

        # ==========================
        # 1. 传统的 <a> 标签
        # ==========================
        anchors = page.query_selector_all("a[href]")
        for a in anchors:
            href = a.get_attribute("href")
            if href:
                absolute_url = urljoin(current_url, href)
                if self._should_visit(absolute_url):
                    found_links.add(absolute_url)

        # ==========================
        # 2. JS 深度挖掘 (Deep Scan)
        # ==========================
        # 需要引入我们刚才定义的提取器
        # from .link_extractor import JsLinkExtractor (确保头部已导入)

        for script in scripts:
            content_to_scan = ""

            # --- 情况 A: 内联脚本 (直接有代码) ---
            if script.is_inline and script.content:
                content_to_scan = script.content

            # --- 情况 B: 外链脚本 (需要下载) ---
            elif script.src:
                absolute_src = urljoin(current_url, script.src)

                # [Step 1] 全局去重检查
                # 如果这个 JS 文件之前已经下载并分析过了，直接跳过
                if absolute_src in self._processed_script_urls:
                    # print(f"[DEBUG] Skipping cached script: {absolute_src}")
                    continue

                # [Step 2] 相关性检查 (Vendor 过滤)
                if not self._is_relevant_script(absolute_src):
                    # 即便是不相关的，也标记为已处理，防止下次重复进行相关性检查（虽然那个很快）
                    self._processed_script_urls.add(absolute_src)
                    continue

                # [Step 3] 下载内容
                #    使用 page.request (APIRequestContext) 可以复用当前页面的 Cookies
                try:
                    resp = page.request.get(absolute_src, timeout=3000)
                    if resp.ok:
                        self._processed_script_urls.add(absolute_src)  # <--- 下载成功后，加入已处理集合

                        body_bytes = resp.body()
                        # 大小限制
                        if len(body_bytes) < 1024 * 1024 * 2:
                            content_to_scan = body_bytes.decode("utf-8", errors="replace")
                            # [可选] 如果你想在 PageAsset 里保留内容，可以在这里赋值
                            # script.content = content_to_scan
                        else:
                            content_to_scan = body_bytes[:512000].decode("utf-8", errors="replace")
                    else:
                        print(f"[WARN] Failed to fetch script {absolute_src}: {resp.status}")
                        # 失败了是否要标记为已处理？
                        # 建议不标记，万一只是网络抖动，下次遇到还可以重试。
                        pass

                except Exception as e:
                    print(f"[DEBUG] Fetch script error {absolute_src}: {e}")
                    continue

            # --- 执行正则提取 ---
            if content_to_scan:
                # 传入 current_url 作为 base，用于把 JS 里提取到的相对路径 '/api/v1' 转为绝对路径
                js_links = JsLinkExtractor.extract_links(content_to_scan, current_url)

                for link in js_links:
                    if self._should_visit(link):
                        found_links.add(link)

        return list(found_links)

    # ==============================
    # 脚本收集
    # ==============================
    def _extract_scripts(self, page: Page) -> List[ScriptAsset]:
        scripts: List[ScriptAsset] = []

        # 外链脚本
        for el in page.query_selector_all("script[src]"):
            src = el.get_attribute("src")
            if not src:
                continue
            
            # 过滤掉不相关的脚本（runtime, polyfills, vendor 等）
            if not self._is_relevant_script(src):
                continue

            script_type = el.get_attribute("type")
            
            # # 尝试下载脚本内容
            # content = None
            # try:
            #     # 注意：src 可能是相对路径，需要转绝对路径
            #     absolute_src = urljoin(page.url, src)
            #     # 使用 playwright 的 APIRequest context 去 fetch
            #     # 简单起见，这里同步 fetch，可能会拖慢速度
            #     resp = page.request.get(absolute_src)
            #     if resp.ok:
            #         text = resp.text()
            #         # 同样做个截断，防止太大
            #         if len(text) > 50000:
            #             content = text[:50000] + "\n/* truncated */"
            #         else:
            #             content = text
            # except Exception as e:
            #     print(f"[WARN] Failed to fetch script {src}: {e}")

            scripts.append(
                ScriptAsset(
                    src=src,
                    content=None,
                    script_type=script_type,
                    is_inline=False,
                )
            )

        # 内联脚本
        for el in page.query_selector_all("script:not([src])"):
            code = el.inner_html()
            # truncated_code = code
            # if code and len(code) > 5000:
            #     truncated_code = code[:5000] + "\n/* truncated */"
            
            script_type = el.get_attribute("type")
            scripts.append(
                ScriptAsset(
                    src=None,
                    content=code,
                    # content=code, # 内联脚本 content 存全量（或者也截断，看需求）
                    script_type=script_type,
                    is_inline=True,
                )
            )

        return scripts

    def _is_relevant_script(self, src: str) -> bool:
        """
        判断脚本是否“值得关注”。
        1. 过滤掉非本站（跨域）的脚本 (CDN, 外部统计等)
        2. 过滤掉常见的库文件、runtime、polyfills 等
        """
        # 1. 检查是否跨域
        try:
            parsed = urlparse(src)
            # 如果有 netloc (域名)，说明是绝对路径或协议相对路径
            if parsed.netloc:
                # 获取 base_url 的 domain (netloc)
                # self._base_origin 是 (scheme, netloc)
                _, base_netloc = self._base_origin
                
                # 简单比对 netloc 是否相等
                # 注意：这里严格限制为“完全同源”（端口也要一致）
                # 如果需要允许子域名，可以改用 endswith 判断
                if parsed.netloc != base_netloc:
                    return False
        except Exception:
            # 解析失败当作不相关
            return False

        # 2. 关键词过滤
        lower_src = src.lower()
        
        # 常见无关文件名关键词
        ignore_keywords = [
            "runtime",
            "polyfills",
            "vendor",
            "jquery",
            "bootstrap",
            "popper",
            "react",
            "vue",
            "angular",
            "lodash",
            "moment",
            "axios",
            "cookieconsent", # 用户截图中出现的
        ]
        
        for kw in ignore_keywords:
            if kw in lower_src:
                return False
                
        return True

    # ==============================
    # 输入控件收集
    # ==============================
    # ==============================
    # 输入控件收集
    # ==============================
    def _extract_inputs(self, page: Page, page_url: str) -> List[InputField]:
        inputs: List[InputField] = []

        # 1. DOM Inputs (input, textarea, select)
        # 增加对 hidden input 的收集 (OWASP 需要)
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
                source="dom",
            )
            self._next_input_id += 1
            inputs.append(field)

        # 2. ContentEditable (富文本输入)
        # 常见于现代前端编辑器
        editables = page.query_selector_all("[contenteditable]")
        for el in editables:
            dom_id = el.get_attribute("id")
            css_selector = self._build_css_selector("div", dom_id, None) # 假设是 div
            
            field = InputField(
                internal_id=self._next_input_id,
                page_url=page_url,
                tag="contenteditable",
                name=None,
                input_type="richtext",
                dom_id=dom_id,
                placeholder=None,
                css_selector=css_selector,
                source="dom",
            )
            self._next_input_id += 1
            inputs.append(field)

        # 3. URL Parameters (Query String)
        # 视为一种特殊的输入点 (source="url_param")
        parsed = urlparse(page_url)
        if parsed.query:
            from urllib.parse import parse_qs
            qs = parse_qs(parsed.query)
            for key, values in qs.items():
                for v in values:
                    field = InputField(
                        internal_id=self._next_input_id,
                        page_url=page_url,
                        tag="url_param",
                        name=key,
                        input_type="text",
                        dom_id=None,
                        placeholder=v, # 把当前值暂存 placeholder 或 meta
                        css_selector="",
                        source="url_param",
                        meta={"value": v}
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

    # ==============================
    # 存储与 Cookie 收集
    # ==============================
    def _extract_storage(self, page: Page) -> tuple[List[dict], List[dict], List[dict]]:
        """
        收集 Cookies, LocalStorage, SessionStorage
        返回: (cookies, local_storage, session_storage)
        """
        # 1. Cookies
        # playwright 直接提供了 context.cookies()，但那是针对整个 context 的
        # page.context.cookies(url) 可以只拿当前 URL 相关的
        raw_cookies = page.context.cookies(page.url)
        cookies = []
        for c in raw_cookies:
            cookies.append({
                "name": c["name"],
                "value": c["value"],
                "domain": c["domain"],
                "path": c["path"],
                "expires": c["expires"],
                "httpOnly": c["httpOnly"],
                "secure": c["secure"],
                "sameSite": c["sameSite"],
            })

        # 2. LocalStorage
        local_storage = []
        try:
            ls_data = page.evaluate("() => JSON.stringify(localStorage)")
            import json
            if ls_data:
                ls_dict = json.loads(ls_data)
                for k, v in ls_dict.items():
                    local_storage.append({"key": k, "value": str(v)})
        except Exception:
            pass

        # 3. SessionStorage
        session_storage = []
        try:
            ss_data = page.evaluate("() => JSON.stringify(sessionStorage)")
            import json
            if ss_data:
                ss_dict = json.loads(ss_data)
                for k, v in ss_dict.items():
                    session_storage.append({"key": k, "value": str(v)})
        except Exception:
            pass

        return cookies, local_storage, session_storage

    # ==============================
    # 注释收集
    # ==============================
    def _extract_comments(self, page: Page) -> List[str]:
        """
        提取 HTML 注释
        """
        return page.evaluate("""() => {
            const comments = [];
            const iterator = document.createNodeIterator(
                document.documentElement,
                NodeFilter.SHOW_COMMENT,
                null,
                false
            );
            let node;
            while (node = iterator.nextNode()) {
                comments.push(node.nodeValue.trim());
            }
            return comments;
        }""")

    def _is_register_page(self, url: str, html: str) -> bool:
        # 简单判断逻辑
        keywords = ["register", "sign-up", "signup", "create account"]
        return any(k in url for k in keywords) or any(k in html.lower()[:1000] for k in keywords)

    def _is_login_page(self, url: str, html: str) -> bool:
        keywords = ["login", "sign-in", "signin"]
        return any(k in url for k in keywords)

    def set_auth_context(self, creds: AuthCredentials):
        """
        将用户提供的凭证应用到 Playwright 浏览器上下文中。
        """
        if creds.cookies and hasattr(self._page.context, 'add_cookies'):
            # Playwright 上下文方法，用于设置会话 Cookies
            self._page.context.add_cookies(creds.cookies)
            print(f"  -> {len(creds.cookies)} cookies injected.")

        # 将 Headers 存储在实例变量中，供攻击阶段使用
        if creds.headers:
            self._auth_headers.update(creds.headers)
            print(f"  -> {len(creds.headers)} headers loaded (Authorization, etc.).")

    def get_current_session_context(self) -> Dict[str, Any]:
        """
        返回一个字典，包含当前活动的 Playwright 页面和授权信息，供 AttackStrategy 使用。
        """
        # 确保返回的是活动的、已设置授权的 Page 实例
        return {
            # 1. 核心客户端：活动的 Playwright Page 实例
            #    XSSAttacker 将用它来发送请求、观察 DOM 变化等
            'playwright_page': self._page,

            # 2. 授权 Headers：包含手动输入的 Authorization Token
            'auth_headers': self._auth_headers,

            # 3. 当前会话的 Cookies (可选，但推荐)
            'current_cookies': self._page.context.cookies(),
        }