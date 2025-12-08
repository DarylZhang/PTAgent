import re
import jsbeautifier
from script.datatypes import Endpoint
from script.llm_service import LLMService


class StaticAnalyzer:
    def __init__(self, llm: LLMService):
        self.llm = llm

    def run(self, js_contents: list[str]) -> list[Endpoint]:
        """
        入口：输入多个 JS 文件内容，输出发现的端点
        """
        endpoints = []
        print(f"[*] Static Analyzer running on {len(js_contents)} JS files...")

        for js_code in js_contents:
            # 1. 预处理：格式化 JS，方便正则和切片
            beautified_js = jsbeautifier.beautify(js_code)

            # 2. 提取潜在的 API 调用切片 (Slicing)
            slices = self._extract_interesting_slices(beautified_js)

            # 3. 分析切片
            for code_slice in slices:
                # 简单正则提取 URL (Baseline)
                url_match = re.search(r"['\"](/[a-zA-Z0-9_/-]+)['\"]", code_slice)

                if url_match:
                    url = url_match.group(1)

                    # 4. 调用 LLM 推断参数 (Innovation Point)
                    # 只有当代码看起来像是在构建请求体时才调用
                    if "JSON.stringify" in code_slice or "body:" in code_slice:
                        print(f"   [+] Complex logic found for {url}, asking LLM to infer schema...")
                        params = self.llm.infer_api_schema(code_slice)
                        endpoints.append(Endpoint(
                            url=url,
                            method="POST",  # 简化的假设，实际应由正则提取
                            params=params,
                            source="static_llm_inferred",
                            context=code_slice
                        ))
                    else:
                        # 简单的 GET 请求
                        endpoints.append(Endpoint(
                            url=url,
                            method="GET",
                            source="static_regex",
                            context=code_slice
                        ))

        return endpoints

    def _extract_interesting_slices(self, js_code: str) -> list[str]:
        """
        简单的切片算法：提取包含 fetch/axios 等关键词的周边代码行
        """
        lines = js_code.split('\n')
        slices = []
        keywords = ['fetch(', 'axios.', 'XMLHttpRequest', '.post(', '.get(']

        for i, line in enumerate(lines):
            if any(k in line for k in keywords):
                # 简单策略：提取前后 5 行作为上下文
                # PhD 改进点：这里应该换成基于 AST 的 Scope 提取
                start = max(0, i - 5)
                end = min(len(lines), i + 5)
                slices.append("\n".join(lines[start:end]))

        return slices