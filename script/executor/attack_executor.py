# script/executor/attack_executor.py

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Dict, Optional

from script.payload.payload_registry import PayloadTemplate
from script.executor.types import TestContext, PlannedTest, TestResult


class AttackExecutor(ABC):
    """
    所有“漏洞类型执行器”的抽象基类。
    比如：
      - XssAttackExecutor 处理 XSS
      - AuthAttackExecutor 处理认证相关
      - SqliAttackExecutor 处理 SQL 注入
    """

    @abstractmethod
    def supports_vuln_type(self, vuln_type: str) -> bool:
        """
        返回该执行器是否支持某种漏洞类型。
        例如 XssAttackExecutor 返回 True 当 vuln_type == "xss"
        """
        raise NotImplementedError

    @abstractmethod
    def execute(
        self,
        context: TestContext,
        planned_test: PlannedTest,
        template: PayloadTemplate,
    ) -> List[TestResult]:
        """
        执行一次 PlannedTest。
        注意：一个 template 里可能包含多个 payload，
        所以这里返回的是 List[TestResult]。
        """
        raise NotImplementedError


class ExecutorRegistry:
    """
    执行器注册表：
    - 注册各个漏洞类型的具体执行器
    - 根据 vuln_type 找到对应执行器
    """

    def __init__(self) -> None:
        self._executors: List[AttackExecutor] = []
        self._index: Dict[str, AttackExecutor] = {}

    def register(self, executor: AttackExecutor, vuln_types: List[str]) -> None:
        """
        注册一个执行器，并声明它支持哪些 vuln_type。
        例如：
          registry.register(XssAttackExecutor(...), ["xss"])
        """
        self._executors.append(executor)
        for vt in vuln_types:
            self._index[vt] = executor

    def get_executor_for(self, vuln_type: str) -> Optional[AttackExecutor]:
        """
        根据 vuln_type 查找执行器。
        如果没注册，就返回 None。
        """
        # 先查直接索引
        if vuln_type in self._index:
            return self._index[vuln_type]

        # 退化为遍历检查（支持 executor 内部逻辑判断）
        for exe in self._executors:
            if exe.supports_vuln_type(vuln_type):
                return exe

        return None