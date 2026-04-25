"""Fuzz targets registry."""

from .json_loose import json_loose_target

# Temporary stub to satisfy existing imports
def get_target(name: str):
    if name == "json_loose":
        return json_loose_target
    raise ValueError(f"Unknown target: {name}")

__all__ = ["json_loose_target", "get_target"]
