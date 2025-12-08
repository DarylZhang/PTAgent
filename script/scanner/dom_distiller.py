# 建议放在：script/scanner/dom_distiller.py
# 或者你当前处理 HTML 的那个文件中

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Set, Optional

from bs4 import BeautifulSoup, Tag, NavigableString  # 需要安装 beautifulsoup4


@dataclass
class DistillConfig:
    """
    配置项：方便以后在论文 / 实验里调参数。
    """
    max_text_len: int = 80          # 每个节点最多保留多少字符的可见文本
    max_event_code_len: int = 120   # 内联事件（onclick=...）最多保留长度
    truncate_marker: str = "..."


class InteractionDomDistiller:
    """
    基于“可交互树”的 DOM 蒸馏器。

    输入：原始 HTML（string）
    输出：语义压缩后的 DSL（string），用于喂给 LLM。
    """

    INTERACTIVE_TAGS: Set[str] = {
        "input", "textarea", "select",
        "button", "a", "form",
    }

    # 可能携带敏感数据的属性名 / 关键词
    DATA_ATTR_KEYWORDS: Set[str] = {
        "token", "jwt", "auth", "key", "secret",
    }

    # 白名单属性：对渗透上下文有用的
    ATTR_WHITELIST: Set[str] = {
        "id", "name", "type", "value", "href", "action", "method",
        "placeholder", "for", "src",
    }

    # 事件属性（需要保留一部分代码）
    EVENT_ATTRS: Set[str] = {
        "onclick", "onsubmit", "onchange", "oninput", "onblur", "onfocus",
    }

    # 直接过滤掉的标签（噪音为主）
    TAGS_TO_DROP: Set[str] = {
        "style", "script", "svg",
    }

    def __init__(self, config: Optional[DistillConfig] = None) -> None:
        self.config = config or DistillConfig()

    # ===========================
    # 对外主入口
    # ===========================
    def distill_html(self, html: str) -> str:
        """
        输入原始 HTML，返回“语义压缩后的 DSL 文本”。

        典型用法：
            distiller = InteractionDomDistiller()
            dsl_text = distiller.distill_html(page_asset.dom_snapshot or page_asset.html)
        """
        soup = BeautifulSoup(html, "html.parser")

        # 通常只关心 <body> 以内的内容
        root: Tag = soup.body or soup

        # step 1: 底向上标记“显著节点”
        salient_map: Dict[Tag, bool] = {}
        self._mark_salient_nodes(root, salient_map)

        # step 2: 自顶向下线性化为 DSL 行
        lines: List[str] = []
        self._linearize(root, salient_map, depth=0, out_lines=lines)

        return "\n".join(lines)

    # ===========================
    # Step 1: 显著性标记
    # ===========================
    def _mark_salient_nodes(self, node: Tag, salient_map: Dict[Tag, bool]) -> bool:
        """
        返回：该节点子树中是否存在“显著节点”。
        逻辑：
          - 自身是交互节点 / 数据节点 ⇒ 显著
          - 子节点有显著 ⇒ 自身也保留（当作结构节点）
        """
        if not isinstance(node, Tag):
            return False

        # 某些标签直接丢弃整个子树
        if node.name in self.TAGS_TO_DROP:
            salient_map[node] = False
            return False

        # 自身是否显著
        is_salient_self = self._is_salient_node(node)

        # 子树是否显著
        is_salient_child = False
        for child in node.children:
            if isinstance(child, Tag):
                child_salient = self._mark_salient_nodes(child, salient_map)
                is_salient_child = is_salient_child or child_salient

        is_salient = is_salient_self or is_salient_child
        salient_map[node] = is_salient
        return is_salient

    def _is_salient_node(self, node: Tag) -> bool:
        """
        判断一个节点自身是否是“显著节点”：
          - 交互节点：input / textarea / select / button / a / form
          - 含 data-* 或 token/jwt 等关键属性
        """
        tag_name = node.name.lower()

        # 交互节点
        if tag_name in self.INTERACTIVE_TAGS:
            return True

        # data-* 或包含敏感关键字的属性
        for attr_name, attr_value in node.attrs.items():
            attr_name_lower = attr_name.lower()
            if attr_name_lower.startswith("data-"):
                return True
            for kw in self.DATA_ATTR_KEYWORDS:
                if kw in attr_name_lower:
                    return True
                if isinstance(attr_value, str) and kw in attr_value.lower():
                    return True

        return False

    # ===========================
    # Step 2: 线性化为 DSL
    # ===========================
    def _linearize(
        self,
        node: Tag,
        salient_map: Dict[Tag, bool],
        depth: int,
        out_lines: List[str],
    ) -> None:
        """
        深度优先遍历显著子树，并输出紧凑的 DSL 行。
        """
        if not isinstance(node, Tag):
            return

        # 如果这个节点子树完全不显著，直接跳过
        if not salient_map.get(node, False):
            return

        # 自身是不是显著节点（而不是仅仅撑结构）
        is_self_salient = self._is_salient_node(node)

        if is_self_salient:
            line = self._render_node_as_dsl(node, depth)
            if line:
                out_lines.append(line)

        # 继续处理子节点
        for child in node.children:
            if isinstance(child, Tag):
                self._linearize(child, salient_map, depth + (1 if is_self_salient else 0), out_lines)

    def _render_node_as_dsl(self, node: Tag, depth: int) -> str:
        """
        把一个“显著节点”渲染成一行 DSL 文本。
        格式示例：
            INPUT id=email name=email type=text placeholder="Your email"
            BUTTON#loginButton text="Log in"
        """
        tag_name = node.name.lower()
        indent = "  " * depth

        # 1) 选择器 / 标识
        elem_id = node.get("id")
        elem_name = node.get("name")

        if elem_id:
            header = f"{tag_name}#{elem_id}"
        elif elem_name:
            header = f"{tag_name}[name={elem_name}]"
        else:
            header = tag_name

        # 2) 白名单属性
        attrs_parts: List[str] = []
        for attr_name, attr_value in node.attrs.items():
            attr_name_lower = attr_name.lower()

            # 跳过事件属性，这里后面单独处理
            if attr_name_lower in self.EVENT_ATTRS:
                continue

            if attr_name_lower in self.ATTR_WHITELIST:
                val_str = self._shorten_str(str(attr_value), self.config.max_text_len)
                attrs_parts.append(f'{attr_name_lower}="{val_str}"')

        # 3) 事件属性
        event_parts: List[str] = []
        for evt in self.EVENT_ATTRS:
            if evt in node.attrs:
                code = str(node.attrs[evt])
                code_short = self._shorten_str(code, self.config.max_event_code_len)
                event_parts.append(f'{evt}="{code_short}"')

        # 4) 可见文本（对 button / a / label / option 等有用）
        text_snippet = ""
        if tag_name in {"button", "a", "option", "label"}:
            text = node.get_text(strip=True)
            if text:
                text_snippet = self._shorten_str(text, self.config.max_text_len)

        # 拼接
        parts: List[str] = [header]
        if attrs_parts:
            parts.extend(attrs_parts)
        if event_parts:
            parts.extend(event_parts)
        if text_snippet:
            parts.append(f'text="{text_snippet}"')

        return indent + " ".join(parts)

    # ===========================
    # 辅助函数
    # ===========================
    def _shorten_str(self, s: str, max_len: int) -> str:
        if len(s) <= max_len:
            return s
        return s[: max_len - len(self.config.truncate_marker)] + self.config.truncate_marker