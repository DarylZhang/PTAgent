# script/utils/base.py
from __future__ import annotations

from typing import Protocol
from typing import List, Dict
# from script.datatypes import Endpoint, Action

class LLMClient(Protocol):
    """
    所有大模型客户端的统一接口。

    只要求实现一个方法：
        complete(prompt: str) -> str

    返回值约定：
        - 返回的是一个“JSON 字符串”
        - 这个 JSON 必须符合 OwaspTop10LLMAnalyzer 里期望的格式：
          {"issues": [ ... ]}
    """

    def complete(self, prompt: str) -> str:
        ...

    def infer_api_schema(self, code_slice: str) -> Dict:
        ...

    # def decide_next_action(self, dom_summary: str) -> Action:
    #     ...
    #
    # def generate_payloads(self, endpoint: Endpoint) -> List[str]:
        ...

    def analyze_response(self, response_text: str) -> bool:
        ...