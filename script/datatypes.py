from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class Endpoint(BaseModel):
    """
    定义的 API 端点或页面路径
    """
    url: str
    method: str = "GET"
    # 参数 Schema，例如 {"username": "string", "age": "int"}
    params: Optional[Dict[str, Any]] = None
    # 来源: 'static_ast' (静态发现) 或 'dynamic_traffic' (动态捕获)
    source: str
    # 上下文: JS 代码片段或 HTML 源码，用于给 LLM 做提示
    context: Optional[str] = None
    tested: bool = False

class VulnerabilityReport(BaseModel):
    """
    漏洞报告
    """
    vuln_type: str    # e.g., "XSS", "SQLi", "Sensitive Data Exposure"
    target_url: str
    payload: str
    severity: str     # High, Medium, Low
    evidence: str     # 响应片段或截图路径

class Action(BaseModel):
    """
    LLM 决定的下一步操作 (Agent Action)
    """
    type: str         # "click", "fill", "navigate", "stop"
    selector: Optional[str] = None
    value: Optional[str] = None
    reasoning: str    # CoT: 为什么要做这个操作