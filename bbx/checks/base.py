
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CheckResult:
    status: str
    summary: str
    request_count: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    kv: dict[str, str] = field(default_factory=dict)
    evidence: list[dict[str, str]] = field(default_factory=list)
    error: str | None = None


class BaseCheck(ABC):
    name: str = 'base'
    description: str = ''
    requires_auth: bool = False
    safe_by_default: bool = True

    @abstractmethod
    def run(self, asset: dict[str, Any], context: Any) -> CheckResult:
        raise NotImplementedError
