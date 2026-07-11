#!/usr/bin/env python3
"""validate_registry.py — G0 claim-registry gate.

Usage:
    python tools/gates/validate_registry.py protocol/claims/registry.json [--schema PATH]

Validates the MindChain/NOOSPHERE claim registry against
protocol/claims/registry.schema.json (JSON-Schema 2020-12) when the
`jsonschema` package is available, otherwise against a built-in minimal
validator covering the same required-field / enum / conditional surface.

Beyond the schema, this gate enforces the plan §1.3-1.4 invariants:
  * top level is {"schema_version": ..., "claims": [...]}
  * claim_id values are unique (a changed threshold is a NEW claim_id)
  * every claim carries non-empty: claim_id, mechanism_id, gate, rollback,
    owner, date, provenance
  * every claim carries all six independent dimensions with legal values:
      evidence_label          in {BUILDABLE, THEORY, DREAM}
      implementation_status   in {NOT_STARTED, PARTIAL, IMPLEMENTED}
      evidence_status         in {UNMEASURED, MEASURED_LAB,
                                  INDEPENDENTLY_REPRODUCED, AUDITED}
      lifecycle               in {DEFINED, ACTIVE, DISABLED, RETIRED,
                                  WITHDRAWN}
      result                  in {UNTESTED, PARTIAL, PASSED, KILLED}
      enabled                 boolean
  * every THEORY claim carries a falsifier: a present, non-empty
    kill_threshold

Exit codes:
    0  registry valid
    1  validation errors (per-claim error list on stderr)
    2  registry file missing or unreadable / schema unusable
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

DIMENSIONS = {
    "evidence_label": {"BUILDABLE", "THEORY", "DREAM"},
    "implementation_status": {"NOT_STARTED", "PARTIAL", "IMPLEMENTED"},
    "evidence_status": {
        "UNMEASURED",
        "MEASURED_LAB",
        "INDEPENDENTLY_REPRODUCED",
        "AUDITED",
    },
    "lifecycle": {"DEFINED", "ACTIVE", "DISABLED", "RETIRED", "WITHDRAWN"},
    "result": {"UNTESTED", "PARTIAL", "PASSED", "KILLED"},
}

REQUIRED_NONEMPTY = (
    "claim_id",
    "mechanism_id",
    "gate",
    "rollback",
    "owner",
    "date",
    "provenance",
)


# --------------------------------------------------------------------------
# Minimal JSON-Schema (2020-12 subset) validator, used when the external
# `jsonschema` package is unavailable.  Supported keywords: type, enum,
# const, required, properties, additionalProperties (boolean form), items,
# minItems, maxItems, minLength, maxLength, pattern, minimum, maximum,
# if/then/else, allOf, anyOf, oneOf, not, and internal "$ref": "#/...".
# --------------------------------------------------------------------------

_TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def _check_type(value, tname: str) -> bool:
    if tname == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if tname == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    py = _TYPE_MAP.get(tname)
    return py is not None and isinstance(value, py) and not (
        py is not bool and isinstance(value, bool) and tname != "boolean"
    )


def _resolve_ref(root, ref: str):
    if not ref.startswith("#"):
        raise ValueError(f"unsupported external $ref: {ref}")
    node = root
    for part in ref.lstrip("#/").split("/"):
        if not part:
            continue
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[part]
    return node


def _mini_validate(instance, schema, root, path: str, errors: list) -> bool:
    """Returns True when instance satisfies schema; appends messages."""
    if schema is True or schema == {}:
        return True
    if schema is False:
        errors.append(f"{path}: disallowed by schema (false)")
        return False

    ok = True
    if "$ref" in schema:
        target = _resolve_ref(root, schema["$ref"])
        if not _mini_validate(instance, target, root, path, errors):
            ok = False

    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_check_type(instance, x) for x in types):
            errors.append(f"{path}: expected type {t}, got {type(instance).__name__}")
            return False  # further keyword checks would be noise

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum {schema['enum']}")
        ok = False
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
        ok = False

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength {schema['minLength']}")
            ok = False
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path}: longer than maxLength {schema['maxLength']}")
            ok = False
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: does not match pattern {schema['pattern']!r}")
            ok = False

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
            ok = False
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: above maximum {schema['maximum']}")
            ok = False

    if isinstance(instance, dict):
        for req in schema.get("required", []):
            if req not in instance:
                errors.append(f"{path}: missing required property {req!r}")
                ok = False
        props = schema.get("properties", {})
        for key, sub in props.items():
            if key in instance:
                if not _mini_validate(instance[key], sub, root, f"{path}.{key}", errors):
                    ok = False
        if schema.get("additionalProperties") is False:
            extra = set(instance) - set(props)
            if extra:
                errors.append(f"{path}: additional properties {sorted(extra)}")
                ok = False

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: fewer than minItems {schema['minItems']}")
            ok = False
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: more than maxItems {schema['maxItems']}")
            ok = False
        items = schema.get("items")
        if items is not None:
            for idx, element in enumerate(instance):
                if not _mini_validate(element, items, root, f"{path}[{idx}]", errors):
                    ok = False

    for sub in schema.get("allOf", []):
        if not _mini_validate(instance, sub, root, path, errors):
            ok = False
    if "anyOf" in schema:
        scratch: list = []
        if not any(
            _mini_validate(instance, sub, root, path, scratch)
            for sub in schema["anyOf"]
        ):
            errors.append(f"{path}: does not satisfy anyOf")
            ok = False
    if "oneOf" in schema:
        scratch = []
        hits = sum(
            1
            for sub in schema["oneOf"]
            if _mini_validate(instance, sub, root, path, scratch)
        )
        if hits != 1:
            errors.append(f"{path}: satisfies {hits} of oneOf branches, expected 1")
            ok = False
    if "not" in schema:
        scratch = []
        if _mini_validate(instance, schema["not"], root, path, scratch):
            errors.append(f"{path}: matches disallowed 'not' schema")
            ok = False

    if "if" in schema:
        scratch = []
        if _mini_validate(instance, schema["if"], root, path, scratch):
            if "then" in schema and not _mini_validate(
                instance, schema["then"], root, path, errors
            ):
                ok = False
        elif "else" in schema and not _mini_validate(
            instance, schema["else"], root, path, errors
        ):
            ok = False

    return ok


def schema_validate(instance, schema) -> list:
    """Validate with jsonschema when available, else the built-in subset."""
    try:
        import jsonschema  # type: ignore

        validator_cls = jsonschema.validators.validator_for(schema)
        validator_cls.check_schema(schema)
        validator = validator_cls(schema)
        return [
            f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
            for err in sorted(validator.iter_errors(instance), key=str)
        ]
    except ImportError:
        errors: list = []
        _mini_validate(instance, schema, schema, "$", errors)
        return errors


# --------------------------------------------------------------------------
# Plan §1.3-1.4 invariants enforced beyond whatever the schema says.
# --------------------------------------------------------------------------


def _nonempty(value) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return len(value) > 0
    return True  # numbers (including 0) and booleans are substantive values


def invariant_errors(doc) -> list:
    errors: list = []
    if not isinstance(doc, dict):
        return ["<root>: registry must be a JSON object"]
    if "schema_version" not in doc or not _nonempty(doc.get("schema_version")):
        errors.append("<root>: missing or empty schema_version")
    claims = doc.get("claims")
    if not isinstance(claims, list):
        errors.append("<root>: 'claims' must be a list")
        return errors

    seen_ids: dict = {}
    for idx, claim in enumerate(claims):
        label = f"claims[{idx}]"
        if not isinstance(claim, dict):
            errors.append(f"{label}: claim must be an object")
            continue
        cid = claim.get("claim_id")
        if isinstance(cid, str) and cid.strip():
            label = f"claims[{idx}] ({cid})"
            if cid in seen_ids:
                errors.append(
                    f"{label}: duplicate claim_id (first at claims[{seen_ids[cid]}]);"
                    " a changed threshold requires a NEW claim_id"
                )
            else:
                seen_ids[cid] = idx

        for field in REQUIRED_NONEMPTY:
            if not _nonempty(claim.get(field)):
                errors.append(f"{label}: missing or empty required field '{field}'")

        for dim, legal in DIMENSIONS.items():
            value = claim.get(dim)
            if value is None:
                errors.append(f"{label}: missing dimension '{dim}'")
            elif value not in legal:
                errors.append(
                    f"{label}: dimension '{dim}' value {value!r} not in {sorted(legal)}"
                )
        if not isinstance(claim.get("enabled"), bool):
            errors.append(f"{label}: dimension 'enabled' must be a boolean")

        if claim.get("evidence_label") == "THEORY" and not _nonempty(
            claim.get("kill_threshold")
        ):
            errors.append(
                f"{label}: THEORY claim without a falsifier"
                " (kill_threshold missing or empty)"
            )
    return errors


def main(argv) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    opts = [a for a in argv[1:] if a.startswith("--")]
    if not args:
        print(
            "usage: validate_registry.py <registry.json> [--schema=PATH]",
            file=sys.stderr,
        )
        return 2
    registry_path = Path(args[0])
    schema_path = None
    for opt in opts:
        if opt.startswith("--schema="):
            schema_path = Path(opt.split("=", 1)[1])
    if schema_path is None:
        schema_path = registry_path.parent / "registry.schema.json"

    if not registry_path.is_file():
        print(
            f"MISSING: registry file not found: {registry_path}\n"
            "The claim registry has not been produced yet"
            " (protocol/claims/registry.json is owned by the claim-registry"
            " workstream). This gate cannot pass without it.",
            file=sys.stderr,
        )
        return 2

    try:
        doc = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot parse {registry_path}: {exc}", file=sys.stderr)
        return 2

    errors: list = []
    if schema_path.is_file():
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: cannot parse schema {schema_path}: {exc}", file=sys.stderr)
            return 2
        errors.extend(f"schema: {msg}" for msg in schema_validate(doc, schema))
    else:
        print(
            f"WARN: schema not found at {schema_path};"
            " applying built-in invariants only",
            file=sys.stderr,
        )

    errors.extend(f"invariant: {msg}" for msg in invariant_errors(doc))

    if errors:
        print(f"FAIL: {registry_path}: {len(errors)} error(s)", file=sys.stderr)
        for msg in errors:
            print(f"  - {msg}", file=sys.stderr)
        return 1

    n = len(doc.get("claims", []))
    print(f"OK: {registry_path}: {n} claim(s) valid")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
