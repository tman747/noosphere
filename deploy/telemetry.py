"""NOOS telemetry-v1 emitter/parser with fail-closed UNKNOWN semantics."""
from __future__ import annotations
import json, math, re, time
from dataclasses import dataclass
from pathlib import Path

LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([^\s]+)(?:\s+(\d+))?$')
@dataclass(frozen=True)
class Result:
    state: str
    value: float | None = None
    reason: str | None = None

def load_contract(path: Path) -> dict:
    data = json.loads(path.read_text("utf-8"))
    if data.get("namespace") != "noos" or data.get("global_semantics",{}).get("unknown_value") != "UNKNOWN": raise ValueError("invalid telemetry contract")
    return data

def parse_labels(raw: str) -> dict[str,str]:
    if not raw: return {}
    labels = {}
    for item in raw.split(","):
        if "=" not in item: raise ValueError("malformed labels")
        key, value = item.split("=", 1)
        if len(value) < 2 or value[0] != '"' or value[-1] != '"': raise ValueError("malformed label value")
        labels[key] = value[1:-1]
    return labels

def parse_sample(line: str, metric: dict, now_seconds: int | None = None) -> Result:
    match = LINE.fullmatch(line.strip())
    if not match or match.group(1) != metric["name"]: return Result("UNKNOWN", reason="malformed")
    try: labels = parse_labels(match.group(2) or ""); value = float(match.group(3))
    except (ValueError, OverflowError): return Result("UNKNOWN", reason="malformed")
    if not math.isfinite(value): return Result("UNKNOWN", reason="malformed")
    allowed = metric["labels"]
    if set(labels) != set(allowed) or any(labels[k] not in allowed[k] for k in labels): return Result("UNKNOWN", reason="malformed")
    if len({tuple(sorted(labels.items()))}) > metric["cardinality_ceiling"]: return Result("UNKNOWN", reason="cardinality_overflow")
    now_seconds = int(time.time()) if now_seconds is None else now_seconds
    if match.group(4) is None: return Result("UNKNOWN", reason="absent_timestamp")
    observed_seconds = int(match.group(4)) // 1000
    if now_seconds - observed_seconds > metric["freshness_deadline_seconds"]: return Result("UNKNOWN", reason="stale")
    return Result("NUMERIC", value=value)

def emit(name: str, value: float, labels: dict[str,str], timestamp_ms: int) -> str:
    if not name.startswith("noos_") or not math.isfinite(value): raise ValueError("invalid noos metric")
    label_text = ",".join(f'{key}="{labels[key]}"' for key in sorted(labels))
    return f"{name}{{{label_text}}} {value:g} {timestamp_ms}" if labels else f"{name} {value:g} {timestamp_ms}"
