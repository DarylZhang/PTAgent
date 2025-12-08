# script/scanner/page_asset.py

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any, Set, Union


# ---------------------------------------------------------
# 基础元素：输入点、API 调用
# ---------------------------------------------------------

@dataclass
class InputField:
    """
    表示页面上的一个可输入控件（input / textarea / select 等）。

    注意这里区分：
      - internal_id: 我们自己赋的数值型 ID，用于 LLM / 分析结果做关联
      - dom_id: HTML 里的 id="..."（可能为空）
    """
    internal_id: int                  # 用于攻击面映射、LLM 返回 related_input_id
    page_url: str                     # 所属页面 URL
    tag: str                          # input / textarea / select ...
    name: Optional[str] = None        # name="..."
    input_type: Optional[str] = None  # type="text/password/email/..."
    dom_id: Optional[str] = None      # 元素的 HTML id 属性（避免和 internal_id 混淆）
    placeholder: Optional[str] = None
    css_selector: str = ""            # 唯一（或尽量唯一）的定位 selector

    # 以后可以扩展：是否可见、是否 disabled、是否 required 等
    meta: Dict[str, Any] = field(default_factory=dict)

    # 输入源类型: "dom" (默认), "url_param", "header", "cookie" 等
    source: str = "dom"


@dataclass
class Cookie:
    """
    表示一个 Cookie 条目。
    """
    name: str
    value: str
    domain: str
    path: str
    expires: float
    httpOnly: bool
    secure: bool
    sameSite: str


@dataclass
class StorageItem:
    """
    表示 LocalStorage 或 SessionStorage 的一个键值对。
    """
    key: str
    value: str


@dataclass
class ApiCall:
    """
    表示在页面生命周期中观察到的一次 API 调用（XHR / fetch）。
    """
    id: int                           # 我们自己的数值 ID，用于关联 / 去重
    url: str
    method: str                       # GET / POST ...
    resource_type: str                # xhr / fetch / websocket / document ...
    request_body: Optional[str] = None
    # 触发该请求的页面（有时重定向后最终 URL 会不同）
    page_url: Optional[str] = None

    request_headers: Dict[str, str] = field(default_factory=dict)
    request_cookies: List[Dict[str, Any]] = field(default_factory=list)
    
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None  # 文本形式的响应体（如有）

    # 以后可以扩展：响应体摘要 / 更多元信息
    meta: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------
# 脚本、可点击元素等页面组件
# ---------------------------------------------------------

@dataclass
class ScriptAsset:
    """
    表示页面相关的一个 JS 资源（外链或内联）。
    """
    # 如果是 <script src="...">，这里是绝对或相对 URL
    src: Optional[str]

    # 无论是内联的还是下载的外链，只要我们在 _collect_links 阶段拿到了内容，都存在这里。
    content: Optional[str] = None

    # script type，例如 text/javascript, module 等
    script_type: Optional[str] = None

    # 是否是内联脚本
    is_inline: bool = False

    # 以后可以扩展：是否包含可疑模式（eval/new Function/fetch/axios 等）
    hints: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClickableElement:
    """
    表示页面上的一个“可交互触发点”，如：
      - <button>
      - <a>
      - <div role="button"> ...
    这些通常是提交、跳转、执行某个 JS 逻辑的入口。
    """
    internal_id: int                  # 我们自己的数值 ID，便于定位 / 关联
    page_url: str
    tag: str                          # button / a / div ...
    css_selector: str                 # 定位该元素的 selector
    text: Optional[str] = None        # 显示文本（可以截断）
    disabled: Optional[bool] = None
    role: Optional[str] = None        # ARIA role 或推断的语义角色（button/link/tab）
    onclick: Optional[str] = None     # 内联 onclick 内容（如有）

    # 以后可以扩展：data-* 属性，绑定的事件（click, submit 等）
    meta: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------
# 预留：通用的“提交单元”（未来替代 <form> 的概念）
# ---------------------------------------------------------

@dataclass
class SubmissionUnit:
    """
    用来表示一次“逻辑上的提交动作”，不依赖 <form> 标签。

    一个 SubmissionUnit 可能对应：
      - 一个按钮 + 一组相关 InputField + 一个 API 调用
      - 或者一个 JS 函数触发的复杂提交流程

    目前可以先作为占位结构，后续在扫描逻辑中逐步填充。
    """
    id: int
    page_url: str

    # 触发这个提交的可点击元素（如按钮），引用 ClickableElement.internal_id
    trigger_clickable_id: Optional[int] = None

    # 参与这次提交的 input 字段（InputField.internal_id 列表）
    related_input_ids: List[int] = field(default_factory=list)

    # 核心映射：API 参数名 -> InputField.internal_id
    # 例如: {"username": 101, "password": 102}
    input_map: Dict[str, int] = field(default_factory=dict)

    # 提交对应的后端 API（ApiCall.id），目前假定主要是一个主 API
    api_call_ids: List[int] = field(default_factory=list)

    # 简单归类：xss_form / login_form / search_box / feedback_form 等
    kind: Optional[str] = None

    # 以后可以加：提交前置条件（captcha/rating/checkbox 等）
    meta: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------
# PageAsset：以 URL 为单位的“页面资产”
# ---------------------------------------------------------

@dataclass
class PageAsset:
    """
    PageAsset = 以 URL 为索引的“页面攻击面资产”。

    它描述了一个页面上所有与你渗透测试相关的“内容”：
      - HTML / DOM 快照
      - JS 脚本
      - 输入点（InputField）
      - 可点击元素（ClickableElement）
      - 在此页面上观察到的 API 调用（ApiCall）
      - 从这些元素/请求推导出的 SubmissionUnit（逻辑提交单元）
    """
    url: str

    # 如果有重定向，可以记录最终 URL（暂时可以为空）
    final_url: Optional[str] = None

    # 页面 <title> 内容（可选）
    title: Optional[str] = None

    # 原始 HTML 文本
    html: Optional[str] = None

    # 清洗后的 HTML 文本
    cleaned_html: Optional[str] = None

    # 或者存一个简化后的 body.outerHTML 片段
    dom_snapshot: Optional[str] = None

    # 关联的 JS 脚本资产（外链 + 内联）
    scripts: List[ScriptAsset] = field(default_factory=list)

    # 页面上的输入控件（包括 DOM input, URL 参数, Hidden fields 等）
    inputs: List[InputField] = field(default_factory=list)

    # 页面上的可点击元素（按钮 / 链接等）
    clickables: List[ClickableElement] = field(default_factory=list)

    # 在该页面“生命周期”中观察到的 API 调用
    api_calls: List[ApiCall] = field(default_factory=list)

    # 从页面行为推导出的“提交单元”
    submissions: List[SubmissionUnit] = field(default_factory=list)

    # --- 新增：OWASP Top 10 所需的扩展信息 ---

    # Cookies (name, value, attributes)
    cookies: List[Cookie] = field(default_factory=list)

    # LocalStorage / SessionStorage
    local_storage: List[StorageItem] = field(default_factory=list)
    session_storage: List[StorageItem] = field(default_factory=list)

    # HTML 注释 (可能泄露敏感信息)
    comments: List[str] = field(default_factory=list)

    # 预留字段：其他任何页面级元信息（安全头、框架指纹等）
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        转成适合给 LLM 或序列化用的 dict 结构。
        """
        return {
            "url": self.url,
            "final_url": self.final_url,
            "title": self.title,
            "html": self.html,
            "cleaned_html": self.cleaned_html,
            "dom_snapshot": self.dom_snapshot,
            "scripts": [asdict(s) for s in self.scripts],
            "inputs": [asdict(i) for i in self.inputs],
            "clickables": [asdict(c) for c in self.clickables],
            "api_calls": [asdict(a) for a in self.api_calls],
            "submissions": [asdict(s) for s in self.submissions],
            "cookies": [asdict(c) for c in self.cookies],
            "local_storage": [asdict(item) for item in self.local_storage],
            "session_storage": [asdict(item) for item in self.session_storage],
            "comments": self.comments,
            "meta": self.meta,
        }


@dataclass  # <--- 必须加上这个装饰器
class AuthCredentials:
    """
    登录成功后获取的凭证集合
    """
    # Playwright cookie format: [{'name': '...', 'value': '...', 'url': '...'}]
    cookies: List[Dict[str, Any]] = field(default_factory=list)

    # HTTP Headers: {"Authorization": "Bearer ..."}
    headers: Dict[str, str] = field(default_factory=dict)

    # LocalStorage: [{"key": "token", "value": "..."}]
    local_storage: List[Dict[str, str]] = field(default_factory=list)

    # SessionStorage
    session_storage: List[Dict[str, str]] = field(default_factory=list)


# ---------------------------------------------------------
# SiteAsset：整个站点的页面资产集合（可选）
# ---------------------------------------------------------

@dataclass
class SiteAsset:
    """
    用来表示某次扫描得到的“站点级攻击面”。
    相当于旧版 AttackSurface 的进化版，但以 PageAsset 为核心。
    """
    base_url: str
    pages: Dict[str, PageAsset] = field(default_factory=dict)

    # [新增]: 独立发现的 API 列表
    # 来源：
    # 1. 爬虫 Probe 阶段发现是 JSON 响应的 URL
    # 2. 从 JS 字符串提取出的 API 路径 (JsLinkExtractor)
    discovered_apis: List[ApiCall] = field(default_factory=list)

    # [新增] 需要鉴权的页面队列
    # 这里的 URL 在未登录扫描时被拦截了，需要在登录成功后进行 "Re-scan"
    auth_required_urls: Set[str] = field(default_factory=set)

    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "pages": {url: p.to_dict() for url, p in self.pages.items()},
            "meta": self.meta,
        }