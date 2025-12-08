from bs4 import BeautifulSoup, Comment, Tag, NavigableString
import re


def clean_html_for_llm(raw_html: str) -> str:
    """
    对 HTML 进行语义降噪，专为 LLM 安全分析设计。
    保留：DOM 结构、输入点、关键属性 (ID, Name, Event Handlers)、注释、安全相关标签 (Meta, Iframe)。
    移除：CSS 类名、Style 属性、SVG、图片内容、无关的布局嵌套。
    """
    if not raw_html:
        return ""

    soup = BeautifulSoup(raw_html, "html.parser")

    # ============================
    # 1. 移除纯噪音标签
    # ============================
    # svg/path: 图标数据，占用大量 Token 且无逻辑价值
    # style: CSS 样式表，对逻辑分析无用
    # link[rel=stylesheet]: 外部 CSS
    # noscript: 通常包含重复内容
    for tag in soup.find_all(["svg", "style", "noscript", "font"]):
        tag.decompose()

    # 处理 link 标签，只移除样式表，保留可能是 prefetch/manifest 等有安全意义的链接
    for tag in soup.find_all("link"):
        if tag.get("rel") == ["stylesheet"]:
            tag.decompose()

    # ============================
    # 2. 定义属性保留白名单
    # ============================
    # 这些属性对 OWASP Top 10 分析至关重要
    ALLOWED_ATTRIBUTES = {
        # 基础标识
        "id", "name", "type", "value", "placeholder", "title", "alt",
        # 表单与数据
        "action", "method", "enctype", "autocomplete", "href", "src", "target",
        # 逻辑控制
        "disabled", "readonly", "required", "checked", "selected", "multiple",
        # 安全相关
        "sandbox", "integrity", "crossorigin", "nonce", "http-equiv", "content",
        # 框架特性 (Vue/React/Angular/HTMX 等常使用 data-*)
        # (代码逻辑中会单独处理 data-*)
    }

    # 危险的事件句柄 (Event Handlers) - 必须保留，XSS 的温床
    # 匹配 on开头的属性，如 onclick, onload, onmouseover
    EVENT_HANDLER_PATTERN = re.compile(r"^on[a-z]+$")

    # ============================
    # 3. 遍历并清洗所有标签
    # ============================
    for tag in soup.find_all(True):
        # --- A. 处理属性 ---
        attrs = list(tag.attrs.keys())
        for attr in attrs:
            # 1. 保留白名单属性
            if attr in ALLOWED_ATTRIBUTES:
                continue

            # 2. 保留 data-* 属性 (现代前端逻辑常驻于此)
            if attr.startswith("data-"):
                continue

            # 3. 保留事件句柄 (onclick 等)
            if EVENT_HANDLER_PATTERN.match(attr):
                continue

            # 4. 其他属性 (class, style, width, height, aria-*, etc.) 全部移除
            del tag[attr]

        # --- B. 特殊标签处理 ---

        # [Images]: 移除 src 中的 Base64，防止 Token 爆炸
        if tag.name == "img":
            src = tag.get("src", "")
            if src.startswith("data:image"):
                tag["src"] = "[BASE64_IMAGE_REMOVED]"

        # [Scripts]: 内联脚本处理
        # 策略：如果太长，进行截断，提示 LLM 去看专门的 Scripts 分析部分
        if tag.name == "script" and not tag.get("src"):
            if tag.string and len(tag.string) > 200:
                # 保留前 50 和后 50 个字符，中间省略
                # 这里的目的是让 LLM 知道这里有一段代码，以及大概是做什么的
                # 具体的代码审计应在 ScriptAsset 环节进行
                tag.string = f"{tag.string[:50]} ... [TRUNCATED_JS_LOGIC] ... {tag.string[-50:]}"

    # ============================
    # 4. 移除空的布局容器 (可选，但建议慎重)
    # ============================
    # 只有当 div/span 没有属性（ID/Name被保留了，Class被删了）且没有内容时才移除
    # 这能极大减少 <div class="..."></div> 留下的 <div></div> 噪音
    for tag in soup.find_all(["div", "span", "section", "container"]):
        if len(tag.attrs) == 0 and not tag.get_text(strip=True):
            # 只有当它不包含重要的子节点（如 input）时才移除
            # 简单判断：如果它全是空白字符
            if not tag.contents or (
                    len(tag.contents) == 1 and isinstance(tag.contents[0], NavigableString) and not tag.contents[
                0].strip()):
                tag.decompose()

    # ============================
    # 5. 保留注释
    # ============================
    # BeautifulSoup 默认保留注释，这里不需要额外操作。
    # 如果想过滤掉条件注释 (IE hacks)，可以在这里加逻辑。
    # 这里的关键是：开发者留下的 TODO 或 敏感路径 往往在注释里。

    return str(soup)


# --- 测试用例 ---
if __name__ == "__main__":
    test_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="csrf-token" content="abc-123-xyz">
        <title>Login</title>
        <style>.hidden { display: none; }</style>
        <script src="jquery.js"></script>
    </head>
    <body class="bg-gray-100 p-4">
        <div class="container mx-auto">
            <svg viewBox="0 0 10 10"><path d="M1..."/></svg>
            <form action="/login" method="POST" class="form-control">
                <input type="hidden" name="redirect_to" value="/dashboard">
                <div class="mb-4">
                    <label class="block text-gray-700">Username</label>
                    <input type="text" id="user" name="username" class="shadow appearance-none border" placeholder="Enter name">
                </div>
                <button type="submit" onclick="submitForm()" class="btn btn-primary">Login</button>
            </form>
            <div class="footer">
                <span class="text-sm">Copyright 2024</span>
            </div>
            <script>
                // Complex logic here
                const a = 1;
                // ... 500 lines ...
                const b = 2;
            </script>
        </div>
    </body>
    </html>
    """

    print(clean_html_for_llm(test_html))