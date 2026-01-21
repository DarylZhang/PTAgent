# script/utils/local_llm_client.py
from __future__ import annotations

from typing import Literal, Optional
import os
from openai import OpenAI, APIConnectionError


class LocalLLMClient:
    """
    统一的本地大模型客户端
    支持 LMStudio 和 Ollama (均通过 OpenAI 兼容协议)
    """

    # 定义默认端口映射
    DEFAULT_URLS = {
        "lmstudio": "http://localhost:1234/v1",
        "ollama": "http://localhost:11434/v1",
    }

    def __init__(
        self,
        backend: Literal["lmstudio", "ollama"] = "ollama",  # 指定后端类型
        model: str = "llama3",  # 模型名称
        base_url: Optional[str] = None,  # 可选：如果端口改了，可以手动覆盖
        temperature: float = 0.1,  # 渗透测试通常需要低温以保证确定性
        max_tokens: int = 4096,
        system_prompt: str = "You are a security analysis assistant. Output in JSON format."
    ):
        self.backend = backend
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.system_prompt = system_prompt

        # 1. 确定 Base URL
        # 如果用户手动传了 base_url，就用用户的；否则根据 backend 自动选择
        if base_url:
            self.api_base = base_url
        else:
            self.api_base = self.DEFAULT_URLS.get(backend, self.DEFAULT_URLS["lmstudio"])

        # 2. 初始化 OpenAI 客户端
        # 本地服务通常不校验 api_key，但 SDK 要求必填
        self.client = OpenAI(
            base_url=self.api_base,
            api_key=f"dummy-{backend}",
        )

        print(f"[*] LocalLLMClient initialized: Backend={backend}, Model={model}, URL={self.api_base}")

    def complete(self, prompt: str) -> str:
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": prompt},
        ]

        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return resp.choices[0].message.content or ""

        except APIConnectionError:
            return f"Error: Could not connect to {self.backend} at {self.api_base}. Is the service running?"
        except Exception as e:
            return f"Error: {str(e)}"