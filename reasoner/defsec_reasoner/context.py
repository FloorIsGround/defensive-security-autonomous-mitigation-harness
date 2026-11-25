"""Build bounded, diff-focused views of collector observations."""

from __future__ import annotations

import json
from typing import Any


_SET_NOTE = "full set available via query_observations with focus_keys"


def _identity_field(field: str, items: list[Any]) -> str | None:
    if not all(isinstance(item, dict) for item in items):
        return None
    if field == "sockets" and all("socket_key" in item for item in items):
        return "socket_key"
    if items:
        preferred = field.removesuffix("s") + "_key"
        keys = sorted(items[0], key=lambda key: (key != preferred, key))
        for key in keys:
            if key.endswith("_key") and all(key in item for item in items):
                return key
    return None


def _identity(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _compact_payload(
    payload: dict[str, Any], focus_keys: set[str] | None, max_items: int
) -> dict[str, Any]:
    compacted = dict(payload)
    for field, items in payload.items():
        if not isinstance(items, list) or (identity := _identity_field(field, items)) is None:
            continue
        keyed = [(_identity(item[identity]), item) for item in items]
        shown = [
            item for key, item in sorted(keyed, key=lambda pair: pair[0])
            if not focus_keys or key in focus_keys
        ][:max_items]
        compacted[field] = {
            "total": len(items),
            "shown": len(shown),
            "items": shown,
            "omitted": len(items) - len(shown),
            "note": _SET_NOTE,
        }
    return compacted


def compact_observation(
    observation: dict[str, Any], *, focus_keys: set[str] | None = None, max_items: int = 40
) -> dict[str, Any]:
    """Keep observation provenance and bound the size of each keyed set."""
    payload = observation.get("payload")
    if not isinstance(payload, dict):
        return observation
    max_items = max(0, max_items)
    compacted = _compact_payload(payload, focus_keys, max_items)
    if payload.get("kind") in ("snapshot", "delta") and isinstance(payload.get("data"), dict):
        compacted["data"] = _compact_payload(payload["data"], focus_keys, max_items)
    return {**observation, "payload": compacted}


def _compacted_sets(observation: dict[str, Any]) -> list[dict[str, Any]]:
    payload = observation.get("payload")
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    fields = list(payload.values())
    if payload.get("kind") in ("snapshot", "delta") and isinstance(data, dict):
        fields.extend(data.values())
    return [
        field for field in fields
        if isinstance(field, dict) and field.get("note") == _SET_NOTE
        and isinstance(field.get("items"), list)
    ]


def has_set_items(observation: dict[str, Any]) -> bool:
    """Check whether a compacted observation contains any selected set items."""
    return any(field["items"] for field in _compacted_sets(observation))


def compact_for_prompt(observation: dict[str, Any], focus_keys: set[str]) -> dict[str, Any]:
    """Fit ordinary sets into one provenance envelope without slicing rows."""
    max_items = 40
    compacted = compact_observation(observation, focus_keys=focus_keys, max_items=max_items)
    while max_items > 0 and has_set_items(compacted):
        encoded = json.dumps(compacted, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) <= 4096:
            break
        max_items //= 2
        compacted = compact_observation(observation, focus_keys=focus_keys, max_items=max_items)
    return compacted


def trigger_diff(outcome: dict[str, Any]) -> dict[str, list[str]]:
    """Read set-diff identities from the trigger's predicate outcome."""
    details = outcome.get("predicate", outcome).get("details", outcome)
    return {
        name: [key for key in details[name] if isinstance(key, str)]
        if isinstance(details.get(name), list) else []
        for name in ("added", "removed", "modified")
    }


def select_observations(
    observations: list[dict[str, Any]], evidence_ids: set[int]
) -> list[dict[str, Any]]:
    """Select cited observations first, then the newest per watch."""
    newest_by_watch: dict[str, dict[str, Any]] = {}
    cited: dict[int, dict[str, Any]] = {}
    for observation in sorted(observations, key=lambda row: row["observation_id"], reverse=True):
        newest_by_watch.setdefault(observation["watch_id"], observation)
        if observation["observation_id"] in evidence_ids:
            cited[observation["observation_id"]] = observation
    return list(cited.values()) + [
        row for row in newest_by_watch.values() if row["observation_id"] not in cited
    ]
