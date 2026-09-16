"""Small, dependency-free contracts shared by workflows and extensions."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import uuid4

ResultStatus = Literal["completed", "failed", "cancelled", "skipped"]


@dataclass
class WorkItem:
    id: str
    operation: str
    input: dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    depends_on: tuple[str, ...] = ()
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkPlan:
    items: list[WorkItem]
    workflow: str = "default"
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunContext:
    run_id: str = field(default_factory=lambda: str(uuid4()))
    workflow: str = "default"
    program_key: str = ""
    services: dict[str, Any] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)
    context_budget: int = 2000
    cancelled: Callable[[], bool] = field(default=lambda: False, repr=False)


@dataclass
class WorkResult:
    item_id: str
    operation: str
    status: ResultStatus
    value: Any = None
    error: str | None = None


@dataclass
class WorkContext:
    run: RunContext
    item: WorkItem
    results: Mapping[str, WorkResult] = field(default_factory=dict)

    @property
    def services(self) -> dict[str, Any]:
        return self.run.services


@dataclass
class ContextBlock:
    text: str
    source: str = ""
    priority: int = 0
    kind: str = "evidence"


@dataclass
class WorkflowEvent:
    name: str
    item_id: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
