from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class Difference:
    path: str
    before: Any
    after: Any


_MISSING = object()


def deep_diff(before: Any, after: Any, path: str = "") -> list[Difference]:
    """Return stable, leaf-oriented differences for JSON-compatible values."""
    if isinstance(before, dict) and isinstance(after, dict):
        differences: list[Difference] = []
        for key in sorted(set(before) | set(after)):
            child_path = f"{path}.{key}" if path else str(key)
            old_value = before.get(key, _MISSING)
            new_value = after.get(key, _MISSING)
            if old_value is _MISSING:
                differences.append(Difference(child_path, None, new_value))
            elif new_value is _MISSING:
                differences.append(Difference(child_path, old_value, None))
            else:
                differences.extend(deep_diff(old_value, new_value, child_path))
        return differences

    if isinstance(before, list) and isinstance(after, list):
        if _is_keyed_list(before) and _is_keyed_list(after):
            return _diff_keyed_lists(before, after, path)
        if _is_scalar_list(before) and _is_scalar_list(after):
            return _diff_scalar_lists(before, after, path)
        if before != after:
            return [Difference(path, before, after)]
        return []

    if before != after:
        return [Difference(path, before, after)]
    return []


def _is_scalar_list(values: Iterable[Any]) -> bool:
    return all(not isinstance(value, (dict, list)) for value in values)


def _is_keyed_list(values: Iterable[Any]) -> bool:
    """True when every entry is a structured value with a stable identity (dicts
    carrying ``identity``). Keyed lists diff entry by entry, so an addition, a
    removal and a redefinition of one entry are reported as exactly those, never
    as a whole-list replacement. Plain scalar lists keep their own diffing."""
    entries = list(values)
    return all(isinstance(value, dict) and value.get("identity") for value in entries)


def _diff_keyed_lists(before: list[Any], after: list[Any], path: str) -> list[Difference]:
    old = {_entry_key(value): value for value in before}
    new = {_entry_key(value): value for value in after}
    differences: list[Difference] = []
    for key in sorted(old.keys() - new.keys()):
        differences.append(Difference(f"{path}[{_bracket(old[key])}]", old[key], None))
    for key in sorted(new.keys() - old.keys()):
        differences.append(Difference(f"{path}[{_bracket(new[key])}]", None, new[key]))
    for key in sorted(old.keys() & new.keys()):
        if old[key] == new[key]:
            continue
        if isinstance(old[key], dict) and isinstance(new[key], dict):
            differences.extend(deep_diff(old[key], new[key], f"{path}[{_bracket(old[key])}]"))
        else:
            differences.append(Difference(f"{path}[{_bracket(old[key])}]", old[key], new[key]))
    return differences


def _entry_key(value: Any) -> str:
    return f"identity:{value['identity']!s}"


def _bracket(value: Any) -> str:
    return str(value["identity"])


def _diff_scalar_lists(before: list[Any], after: list[Any], path: str) -> list[Difference]:
    old = {_stable_scalar(value): value for value in before}
    new = {_stable_scalar(value): value for value in after}
    differences = [Difference(f"{path}[]", old[key], None) for key in sorted(old.keys() - new.keys())]
    differences.extend(Difference(f"{path}[]", None, new[key]) for key in sorted(new.keys() - old.keys()))
    return differences


def _stable_scalar(value: Any) -> str:
    return f"{type(value).__name__}:{value!s}"
