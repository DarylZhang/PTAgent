# script/llm/base.py
from __future__ import annotations

from typing import Protocol


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