# script/utils/lmstudio_client.py
from __future__ import annotations

from typing import Optional, List
import json

from openai import OpenAI


class LMStudioClient:
    """
    通用本地大模型客户端（LMStudio）
    实现 LLMClient 接口：complete(prompt: str) -> str
    """

    def __init__(
        self,
        model: str = "openai/gpt-oss-120b",
        base_url: str = "http://localhost:1234/v1",  # LMStudio 默认 API
        temperature: float = 0.4,
        max_tokens: int = 2048,
        system_prompt: str = "You are a security analysis assistant."
    ):
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.system_prompt = system_prompt

        # 创建客户端（兼容 LMStudio / LocalAI / Ollama）
        self.client = OpenAI(
            base_url=self.base_url,
            api_key="dummy",      # 必填但 LMStudio / LocalAI / Ollama 会忽略
        )

    def complete(self, prompt: str) -> str:
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": prompt},
        ]

        resp = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

        # LMStudio / LocalAI / Ollama-compatible OpenAI API 返回格式一致
        text = resp.choices[0].message.content

        # 统一返回 JSON（交给 analyzer 用 json.loads() 解析）
        return text or ""