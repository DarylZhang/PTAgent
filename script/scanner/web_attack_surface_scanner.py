# 文件：web_attack_surface_scanner.py

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Any
from urllib.parse import urlparse, urljoin

from playwright.sync_api import sync_playwright, Page, Request


@dataclass
class InputField:
    """Represents a potential input point in the page."""
    id: int
    page_url: str
    tag: str               # e.g. input, textarea
    name: Optional[str]
    input_type: Optional[str]
    id: Optional[str]
    placeholder: Optional[str]
    css_selector: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FormInfo:
    """Represents an HTML form and its related inputs."""
    page_url: str
    action: Optional[str]
    method: str
    css_selector: str
    input_selectors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ApiCall:
    """Represents a network API call captured during browsing."""
    id: int
    url: str
    method: str
    resource_type: str     # xhr, fetch, document, etc.
    request_post_data: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PageInfo:
    """Represents a page that was visited."""
    url: str
    discovered_links: List[str] = field(default_factory=list)
    discovered_hash_routes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackSurface:
    """Overall attack surface discovered for a given base URL."""
    base_url: str
    pages: List[PageInfo] = field(default_factory=list)
    inputs: List[InputField] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    api_calls: List[ApiCall] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "pages": [p.to_dict() for p in self.pages],
            "inputs": [i.to_dict() for i in self.inputs],
            "forms": [f.to_dict() for f in self.forms],
            "api_calls": [a.to_dict() for a in self.api_calls],
        }


class WebAttackSurfaceScanner:
    """
    Use Playwright to explore a web application and discover potential attack points.

    Current capabilities:
    - Visit pages starting from base_url (limited depth).
    - Collect all input/textarea elements as potential injection points.
    - Collect form-level information (action, method, related inputs).
    - Capture XHR/fetch requests as potential API endpoints.
    - Discover hash-based SPA routes (e.g., /#/login).
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = 2,
        headless: bool = True,
        same_origin_only: bool = True,
    ):
        """
        :param base_url: Entry URL, e.g. 'http://localhost:3000'
        :param max_depth: Max click depth for crawling links.
        :param headless: Run browser in headless mode if True.
        :param same_origin_only: Restrict crawling to same scheme+host+port.
        """
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.headless = headless
        self.same_origin_only = same_origin_only

        self._visited: Set[str] = set()
        self._attack_surface = AttackSurface(base_url=self.base_url)

        parsed = urlparse(self.base_url)
        self._base_origin = (parsed.scheme, parsed.netloc)

    # -------------------------
    # Public API
    # -------------------------

    def scan(self) -> AttackSurface:
        """Main entry to perform scanning and return the discovered attack surface."""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context()

            # Capture API calls at context level
            context.on("request", self._on_request)

            page = context.new_page()

            # Start crawling from base_url
            self._crawl(page, self.base_url, depth=0)

            browser.close()

        return self._attack_surface

    def pretty_print(self) -> None:
        """Print a human-readable summary of the discovered attack surface."""
        surface = self._attack_surface
        print(f"\n=== Attack Surface for {surface.base_url} ===\n")

        print("Visited pages:")
        for page in surface.pages:
            print(f"  - {page.url}")
            if page.discovered_hash_routes:
                print("    Hash routes:")
                for hr in page.discovered_hash_routes:
                    print(f"      * {hr}")
        print()

        print("Forms:")
        for form in surface.forms:
            print(
                f"  - Page: {form.page_url}\n"
                f"    Method: {form.method}, action={form.action}\n"
                f"    Selector: {form.css_selector}\n"
                f"    Inputs: {form.input_selectors}\n"
            )

        print("Input fields (potential injection points):")
        for inp in surface.inputs:
            print(
                f"  - Page: {inp.page_url}\n"
                f"    Tag: {inp.tag}, name={inp.name}, type={inp.input_type}, "
                f"id={inp.id}, placeholder={inp.placeholder}\n"
                f"    Selector: {inp.css_selector}\n"
            )

        print("Captured API calls (XHR/fetch):")
        for api in surface.api_calls:
            print(f"  - {api.method} {api.url} [{api.resource_type}]")
        print()

    # -------------------------
    # Internal event handlers
    # -------------------------

    def _on_request(self, request: Request) -> None:
        """Capture potential API calls such as XHR/fetch."""
        resource_type = request.resource_type

        # Only consider xhr/fetch
        if resource_type not in ("xhr", "fetch"):
            return

        # ⭐ Only accept same-origin requests
        parsed = urlparse(request.url)
        if (parsed.scheme, parsed.netloc) != self._base_origin:
            return

        api_call = ApiCall(
            id=len(self._attack_surface.api_calls),
            url=request.url,
            method=request.method,
            resource_type=resource_type,
            request_post_data=request.post_data or None,
        )
        self._attack_surface.api_calls.append(api_call)

    # -------------------------
    # Internal crawling logic
    # -------------------------

    def _crawl(self, page: Page, url: str, depth: int) -> None:
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

        # ⭐ 关键：检查最终加载的页面是不是还在同一个 origin
        final_url = page.url
        parsed_final = urlparse(final_url)
        if (parsed_final.scheme, parsed_final.netloc) != self._base_origin:
            # 已经跳到了外站（比如 GitHub）：
            # 只记录原始请求的 URL，但不在这个 DOM 上继续收集任何输入 / 链接
            page_info = PageInfo(url=url)
            self._attack_surface.pages.append(page_info)
            return

        # 下面这部分只对“仍然在 localhost:3000 上”的页面执行
        page_info = PageInfo(url=url)
        self._attack_surface.pages.append(page_info)

        self._collect_inputs(page, url)
        self._collect_forms(page, url)
        self._collect_hash_routes(page, page_info)

        links = self._collect_links(page, url)
        page_info.discovered_links = links

        for link in links:
            self._crawl(page, link, depth + 1)

    def _should_visit(self, url: str) -> bool:
        """Check whether the URL should be visited."""
        parsed = urlparse(url)

        # Ignore non-http(s)
        if parsed.scheme not in ("http", "https"):
            return False

        if self.same_origin_only:
            if (parsed.scheme, parsed.netloc) != self._base_origin:
                return False

        return True

    def _collect_links(self, page: Page, current_url: str) -> List[str]:
        """Collect anchor links from current page."""
        links: List[str] = []

        anchors = page.query_selector_all("a[href]")
        for a in anchors:
            href = a.get_attribute("href")
            if not href:
                continue

            # Resolve relative URL
            absolute_url = urljoin(current_url, href)

            if self._should_visit(absolute_url):
                links.append(absolute_url)

        # De-duplicate while preserving order
        unique_links: List[str] = []
        seen: Set[str] = set()
        for link in links:
            if link not in seen:
                seen.add(link)
                unique_links.append(link)

        return unique_links

    def _collect_inputs(self, page: Page, page_url: str) -> None:
        """Collect potential input fields (HTML form inputs, textareas, etc.)."""
        selector = "input, textarea"
        elements = page.query_selector_all(selector)

        for idx, el in enumerate(elements):
            tag_name = el.evaluate("el => el.tagName.toLowerCase()")
            name = el.get_attribute("name")
            input_type = el.get_attribute("type")
            element_id = el.get_attribute("id")
            placeholder = el.get_attribute("placeholder")

            css_selector = self._build_css_selector(tag_name, name, element_id, idx)

            input_field = InputField(
                id=len(self._attack_surface.inputs),
                page_url=page_url,
                tag=tag_name,
                name=name,
                input_type=input_type,
                placeholder=placeholder,
                css_selector=css_selector,
            )
            self._attack_surface.inputs.append(input_field)

    def _collect_forms(self, page: Page, page_url: str) -> None:
        """Collect form elements and map them to input selectors."""
        # ⭐ 先判断当前页面是否还是同源
        current_url = page.url
        parsed = urlparse(current_url)
        if (parsed.scheme, parsed.netloc) != self._base_origin:
            # 外部站点（比如 GitHub），不收集表单
            return

        form_elements = page.query_selector_all("form")
        for idx, form in enumerate(form_elements):
            action = form.get_attribute("action")
            method = (form.get_attribute("method") or "GET").upper()

            form_id = form.get_attribute("id")
            if form_id:
                form_selector = f"form#{form_id}"
            else:
                form_selector = f"form:nth-of-type({idx + 1})"

            input_selectors: List[str] = []
            inner_inputs = form.query_selector_all("input, textarea")
            for jdx, inp in enumerate(inner_inputs):
                tag_name = inp.evaluate("el => el.tagName.toLowerCase()")
                name = inp.get_attribute("name")
                element_id = inp.get_attribute("id")
                css_sel = self._build_css_selector(tag_name, name, element_id, jdx)
                input_selectors.append(css_sel)

            form_info = FormInfo(
                page_url=page_url,
                action=action,
                method=method,
                css_selector=form_selector,
                input_selectors=input_selectors,
            )
            self._attack_surface.forms.append(form_info)

    def _collect_hash_routes(self, page: Page, page_info: PageInfo) -> None:
        """
        Collect hash-based routes that appear in the DOM, commonly used in SPA:
        e.g. href="#/login" or href="/#/search"
        """
        anchors = page.query_selector_all("a[href^='#'], a[href*='#/']")
        routes: Set[str] = set()

        for a in anchors:
            href = a.get_attribute("href")
            if not href:
                continue
            routes.add(href)

        page_info.discovered_hash_routes = sorted(routes)

    @staticmethod
    def _build_css_selector(
        tag: str,
        name: Optional[str],
        element_id: Optional[str],
        index: int,
    ) -> str:
        """
        Build a simple CSS selector for the element.
        This does not guarantee uniqueness but is useful for later reference.
        """
        if element_id:
            return f"{tag}#{element_id}"
        if name:
            return f'{tag}[name="{name}"]'
        # Fallback to nth-of-type
        return f"{tag}:nth-of-type({index + 1})"