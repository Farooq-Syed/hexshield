"""Registry of defensive tools. New tools self-register via the @register
decorator — this is the extension point for adding more tools later."""

from __future__ import annotations

from typing import Dict, List

from .base import DefenseTool

_registry: Dict[str, DefenseTool] = {}


def register(tool_cls):
    """Class decorator: add a DefenseTool subclass to the registry."""
    inst = tool_cls()
    _registry[inst.name] = inst
    return tool_cls


class ToolRegistry:
    @staticmethod
    def all() -> List[DefenseTool]:
        return list(_registry.values())

    @staticmethod
    def get(name: str) -> DefenseTool:
        return _registry[name]

    @staticmethod
    def has(name: str) -> bool:
        return name in _registry

    @staticmethod
    def names() -> List[str]:
        return sorted(_registry.keys())

    @staticmethod
    def by_category() -> Dict[str, List[DefenseTool]]:
        out: Dict[str, List[DefenseTool]] = {}
        for t in _registry.values():
            out.setdefault(t.category, []).append(t)
        return out