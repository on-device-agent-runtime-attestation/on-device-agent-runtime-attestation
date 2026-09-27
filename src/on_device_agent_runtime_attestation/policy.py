from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class ToolRequest:
    agent_identifier: str
    tool: str
    arguments: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Policy:
    allowed_tools_by_role: dict[str, frozenset[str]] = field(default_factory=dict)
    allowed_domains: frozenset[str] = frozenset({"example.local"})
    denied_secret_markers: tuple[str, ...] = ("sk-", "BEGIN PRIVATE KEY", "secret://raw")

    @classmethod
    def default(cls) -> Policy:
        return cls(
            allowed_tools_by_role={
                "assistant": frozenset(
                    {
                        "calendar.create",
                        "db.query",
                        "email.send",
                        "fs.read",
                        "fs.write",
                        "http.get",
                        "http.post",
                        "model-context-protocol.math.add",
                        "model-context-protocol.notes.search",
                        "model-context-protocol.weather.get",
                        "search.web",
                    }
                ),
                "devops": frozenset(
                    {
                        "code.run",
                        "db.query",
                        "fs.read",
                        "fs.write",
                        "http.get",
                        "http.post",
                        "model-context-protocol.math.add",
                        "model-context-protocol.notes.search",
                        "model-context-protocol.weather.get",
                        "search.web",
                        "shell.exec",
                    }
                ),
            }
        )

    def tool_allowed(self, role: str, request: ToolRequest) -> bool:
        return request.tool in self.allowed_tools_by_role.get(role, frozenset())

    def destination_allowed(self, request: ToolRequest) -> bool:
        for key in ("url", "to"):
            value = request.arguments.get(key)
            if isinstance(value, str) and value:
                domain = self._domain_from_value(value)
                if domain and not (domain == "example.local" or domain.endswith(".example.local")):
                    return False
        return True

    def contains_secret_marker(self, request: ToolRequest) -> bool:
        serialized = repr(request.arguments)
        return any(marker in serialized for marker in self.denied_secret_markers)

    @staticmethod
    def _domain_from_value(value: str) -> str | None:
        if "@" in value and "://" not in value:
            return value.rsplit("@", 1)[1].lower()
        parsed = urlparse(value)
        return parsed.hostname.lower() if parsed.hostname else None
