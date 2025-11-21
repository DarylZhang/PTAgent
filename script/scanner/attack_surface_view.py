# script/scanner/attack_surface_view.py

from dataclasses import dataclass, asdict
from typing import List, Dict, Any
from urllib.parse import urlparse

from .web_attack_surface_scanner import AttackSurface


@dataclass
class LlmInputField:
    id: int
    page_url: str
    css_selector: str
    tag: str
    input_type: str | None
    name: str | None
    placeholder: str | None


@dataclass
class LlmEndpoint:
    id: int
    method: str         # GET / POST ...
    path: str           # /api/Challenges
    has_query: bool     # 是否出现过 query 参数，比如 ?name=xxx


@dataclass
class LlmAttackSurfaceView:
    """
    这是专门给 LLM 用的“简化版攻击面视图”。
    """
    base_url: str
    pages: List[str]
    hash_routes: List[str]
    inputs: List[LlmInputField]
    endpoints: List[LlmEndpoint]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "pages": self.pages,
            "hash_routes": self.hash_routes,
            "inputs": [asdict(i) for i in self.inputs],
            "endpoints": [asdict(e) for e in self.endpoints],
        }


def _normalize_path(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path or "/"


def build_llm_attack_surface_view(surface: AttackSurface) -> LlmAttackSurfaceView:
    """
    把原始 AttackSurface 转成适合 LLM 看的精简结构。
    """
    # 1. 页面列表
    pages = [p.url for p in surface.pages]

    # 2. 所有出现过的 hash routes
    hash_set: set[str] = set()
    for p in surface.pages:
        for hr in p.discovered_hash_routes:
            hash_set.add(hr)

    # 3. 输入点
    llm_inputs: List[LlmInputField] = []
    for inp in surface.inputs:
        llm_inputs.append(
            LlmInputField(
                id=inp.id,
                page_url=inp.page_url,
                css_selector=inp.css_selector,
                tag=inp.tag,
                input_type=inp.input_type,
                name=inp.name,
                placeholder=inp.placeholder,
            )
        )

    # 4. API endpoint，做去重 + 规范化
    endpoint_map: dict[tuple[str, str], LlmEndpoint] = {}
    for api in surface.api_calls:
        path = _normalize_path(api.url)
        key = (api.method.upper(), path)
        has_query = "?" in api.url

        if key not in endpoint_map:
            endpoint_map[key] = LlmEndpoint(
                id=api.id,
                method=api.method.upper(),
                path=path,
                has_query=has_query,
            )
        else:
            # 如果之前没有 query，现在发现有，就更新
            if has_query:
                endpoint_map[key].has_query = True

    endpoints = list(endpoint_map.values())

    return LlmAttackSurfaceView(
        base_url=surface.base_url,
        pages=pages,
        hash_routes=sorted(hash_set),
        inputs=llm_inputs,
        endpoints=endpoints,
    )