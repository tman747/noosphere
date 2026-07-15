from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]
VECTOR_DIR = ROOT / "protocol" / "vectors" / "wwm-web-capacity-v1"
SCHEMA_PATH = ROOT / "protocol" / "schemas" / "wwm-web-capacity-v1.schema.json"
MANIFEST_PATH = VECTOR_DIR / "manifest.json"
VECTORS_PATH = VECTOR_DIR / "vectors.json"

SCHEMA_KEYWORDS = {
    "$schema",
    "$id",
    "title",
    "description",
    "$ref",
    "$defs",
    "type",
    "const",
    "enum",
    "pattern",
    "format",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "multipleOf",
    "required",
    "properties",
    "additionalProperties",
    "minItems",
    "maxItems",
    "uniqueItems",
    "items",
    "allOf",
    "oneOf",
    "if",
    "then",
    "else",
}
SCHEMA_CHILD_MAP_KEYWORDS = {"$defs", "properties"}
SCHEMA_CHILD_LIST_KEYWORDS = {"allOf", "oneOf"}
SCHEMA_CHILD_SINGLE_KEYWORDS = {"items", "if", "then", "else", "additionalProperties"}


def canonical_bytes(value: object) -> bytes:
    """RFC 8785 bytes for this fixture's I-JSON scalar subset (no floats)."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _json_equal(left: object, right: object) -> bool:
    return type(left) is type(right) and canonical_bytes(left) == canonical_bytes(right)


class Draft202012LocalValidator:
    """Complete evaluator for every assertion keyword used by the frozen schema."""

    def __init__(self, root_schema: dict[str, object]):
        self.root = root_schema

    def _resolve(self, reference: str) -> dict[str, object]:
        if not reference.startswith("#/"):
            raise AssertionError(f"unsupported non-local $ref: {reference}")
        node: object = self.root
        for raw_part in reference[2:].split("/"):
            part = raw_part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                raise AssertionError(f"unresolved $ref: {reference}")
            node = node[part]
        if not isinstance(node, dict):
            raise AssertionError(f"$ref does not name a schema: {reference}")
        return node

    @staticmethod
    def _type_matches(expected: str, instance: object) -> bool:
        if expected == "object":
            return isinstance(instance, dict)
        if expected == "array":
            return isinstance(instance, list)
        if expected == "string":
            return isinstance(instance, str)
        if expected == "integer":
            return isinstance(instance, int) and not isinstance(instance, bool)
        if expected == "number":
            return isinstance(instance, (int, float)) and not isinstance(instance, bool)
        if expected == "boolean":
            return isinstance(instance, bool)
        if expected == "null":
            return instance is None
        raise AssertionError(f"unsupported JSON Schema type: {expected}")

    @staticmethod
    def _format_valid(name: str, instance: str) -> bool:
        if name != "uri":
            raise AssertionError(f"unsupported format: {name}")
        if any(character.isspace() for character in instance):
            return False
        parsed = urlsplit(instance)
        return bool(parsed.scheme and parsed.netloc)

    def is_valid(self, instance: object, schema: dict[str, object] | None = None) -> bool:
        return not self.errors(instance, schema, fail_fast=True)

    def errors(
        self,
        instance: object,
        schema: dict[str, object] | None = None,
        path: str = "$",
        fail_fast: bool = False,
    ) -> list[str]:
        current = self.root if schema is None else schema
        errors: list[str] = []

        def reject(message: str) -> bool:
            errors.append(f"{path}: {message}")
            return fail_fast

        reference = current.get("$ref")
        if reference is not None:
            referenced = self._resolve(str(reference))
            errors.extend(self.errors(instance, referenced, path, fail_fast))
            if errors and fail_fast:
                return errors

        for index, subschema in enumerate(current.get("allOf", [])):
            nested = self.errors(instance, subschema, f"{path}.allOf[{index}]", fail_fast)
            errors.extend(nested)
            if errors and fail_fast:
                return errors

        if "oneOf" in current:
            matching = sum(self.is_valid(instance, subschema) for subschema in current["oneOf"])
            if matching != 1 and reject(f"oneOf matched {matching} schemas, expected exactly one"):
                return errors

        if "if" in current:
            branch = current.get("then") if self.is_valid(instance, current["if"]) else current.get("else")
            if branch is not None:
                errors.extend(self.errors(instance, branch, path, fail_fast))
                if errors and fail_fast:
                    return errors

        expected_type = current.get("type")
        if expected_type is not None:
            expected_types = [expected_type] if isinstance(expected_type, str) else expected_type
            if not any(self._type_matches(kind, instance) for kind in expected_types):
                reject(f"expected type {expected_type!r}")
                return errors

        if "const" in current and not _json_equal(instance, current["const"]):
            if reject(f"does not equal const {current['const']!r}"):
                return errors
        if "enum" in current and not any(_json_equal(instance, item) for item in current["enum"]):
            if reject("is not an enum member"):
                return errors

        if isinstance(instance, str):
            if "minLength" in current and len(instance) < current["minLength"]:
                if reject("is shorter than minLength"):
                    return errors
            if "maxLength" in current and len(instance) > current["maxLength"]:
                if reject("is longer than maxLength"):
                    return errors
            if "pattern" in current and re.search(current["pattern"], instance) is None:
                if reject("does not match pattern"):
                    return errors
            if "format" in current and not self._format_valid(current["format"], instance):
                if reject(f"does not satisfy format {current['format']}"):
                    return errors

        if isinstance(instance, (int, float)) and not isinstance(instance, bool):
            if "minimum" in current and instance < current["minimum"]:
                if reject("is below minimum"):
                    return errors
            if "maximum" in current and instance > current["maximum"]:
                if reject("is above maximum"):
                    return errors
            if "multipleOf" in current and instance % current["multipleOf"] != 0:
                if reject("is not a multipleOf value"):
                    return errors

        if isinstance(instance, dict):
            required = current.get("required", [])
            missing = [name for name in required if name not in instance]
            if missing and reject(f"missing required properties {missing!r}"):
                return errors
            properties = current.get("properties", {})
            if current.get("additionalProperties") is False:
                unexpected = sorted(set(instance) - set(properties))
                if unexpected and reject(f"unexpected properties {unexpected!r}"):
                    return errors
            for name, subschema in properties.items():
                if name in instance:
                    errors.extend(
                        self.errors(instance[name], subschema, f"{path}.{name}", fail_fast)
                    )
                    if errors and fail_fast:
                        return errors

        if isinstance(instance, list):
            if "minItems" in current and len(instance) < current["minItems"]:
                if reject("has fewer than minItems"):
                    return errors
            if "maxItems" in current and len(instance) > current["maxItems"]:
                if reject("has more than maxItems"):
                    return errors
            if current.get("uniqueItems"):
                encoded = [canonical_bytes(item) for item in instance]
                if len(encoded) != len(set(encoded)) and reject("has duplicate items"):
                    return errors
            if "items" in current:
                for index, item in enumerate(instance):
                    errors.extend(
                        self.errors(item, current["items"], f"{path}[{index}]", fail_fast)
                    )
                    if errors and fail_fast:
                        return errors

        return errors


# Minimal, independent RFC 8032 verification. It prevents a hex-shaped fixture from
# being mistaken for a valid signature without adding a non-repository dependency.
_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_xrecover(y: int, sign: int) -> int:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P:
        x = x * _ED_I % _ED_P
    if (x * x - xx) % _ED_P:
        raise ValueError("point is not on Ed25519")
    return _ED_P - x if (x & 1) != sign else x


def _ed_decode(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise ValueError("wrong encoded point length")
    value = int.from_bytes(encoded, "little")
    y = value & ((1 << 255) - 1)
    if y >= _ED_P:
        raise ValueError("non-canonical Ed25519 y coordinate")
    x = _ed_xrecover(y, value >> 255)
    return x, y, 1, x * y % _ED_P


def _ed_add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _ED_P
    b = (y1 + x1) * (y2 + x2) % _ED_P
    c = 2 * _ED_D * t1 * t2 % _ED_P
    d = 2 * z1 * z2 % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P


def _ed_scalar(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        scalar >>= 1
    return result


def _ed_encode(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    z_inverse = pow(z, _ED_P - 2, _ED_P)
    x, y = x * z_inverse % _ED_P, y * z_inverse % _ED_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_ED_BASE_Y = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_BASE_X = _ed_xrecover(_ED_BASE_Y, 0)
_ED_BASE = (_ED_BASE_X, _ED_BASE_Y, 1, _ED_BASE_X * _ED_BASE_Y % _ED_P)


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        r_encoded, scalar_encoded = signature[:32], signature[32:]
        scalar = int.from_bytes(scalar_encoded, "little")
        if scalar >= _ED_L:
            return False
        public_point = _ed_decode(public_key)
        r_point = _ed_decode(r_encoded)
    except ValueError:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(r_encoded + public_key + message).digest(), "little"
    ) % _ED_L
    expected = _ed_add(r_point, _ed_scalar(public_point, challenge))
    return _ed_encode(_ed_scalar(_ED_BASE, scalar)) == _ed_encode(expected)


def signed_records(value: object):
    if isinstance(value, dict):
        signature = value.get("signature")
        if isinstance(signature, dict) and signature.get("suite") == "Ed25519":
            yield value
        for nested in value.values():
            yield from signed_records(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from signed_records(nested)


class WwmWebCapacityVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema_bytes = SCHEMA_PATH.read_bytes()
        cls.vector_bytes = VECTORS_PATH.read_bytes()
        cls.schema = json.loads(cls.schema_bytes)
        cls.vectors = json.loads(cls.vector_bytes)
        cls.manifest = json.loads(MANIFEST_PATH.read_bytes())
        cls.validator = Draft202012LocalValidator(cls.schema)

    def test_manifest_file_hashes_and_counts(self) -> None:
        file_entry = self.manifest["files"]["vectors.json"]
        self.assertEqual(file_entry["bytes"], len(self.vector_bytes))
        self.assertEqual(file_entry["sha256"], hashlib.sha256(self.vector_bytes).hexdigest())
        schema_entry = self.manifest["schema"]
        self.assertEqual(schema_entry["bytes"], len(self.schema_bytes))
        self.assertEqual(schema_entry["sha256"], hashlib.sha256(self.schema_bytes).hexdigest())
        self.assertEqual(self.manifest["counts"]["positive"], len(self.vectors["positives"]))
        self.assertEqual(self.manifest["counts"]["negative"], len(self.vectors["negatives"]))

    def test_vector_shape_ids_and_canonical_hashes(self) -> None:
        self.assertEqual(self.vectors["format"], "noos/wwm-web-capacity/v1/vectors/v1")
        all_vectors = self.vectors["positives"] + self.vectors["negatives"]
        identifiers = [vector["id"] for vector in all_vectors]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        for vector in all_vectors:
            with self.subTest(vector=vector["id"]):
                self.assertRegex(vector["id"], r"^[a-z0-9_]+$")
                self.assertEqual(vector["canonical_sha256"], canonical_sha256(vector["instance"]))
                if "context" in vector:
                    self.assertEqual(vector["context_sha256"], canonical_sha256(vector["context"]))
                else:
                    self.assertNotIn("context_sha256", vector)

    def test_local_validator_covers_every_schema_keyword(self) -> None:
        found: set[str] = set()

        def visit(schema: object) -> None:
            if not isinstance(schema, dict):
                return
            for keyword, value in schema.items():
                if keyword.startswith("x-"):
                    continue
                found.add(keyword)
                if keyword in SCHEMA_CHILD_MAP_KEYWORDS:
                    for child in value.values():
                        visit(child)
                elif keyword in SCHEMA_CHILD_LIST_KEYWORDS:
                    for child in value:
                        visit(child)
                elif keyword in SCHEMA_CHILD_SINGLE_KEYWORDS and isinstance(value, dict):
                    visit(value)

        visit(self.schema)
        self.assertEqual(set(), found - SCHEMA_KEYWORDS)
        self.assertEqual(self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_every_top_level_record_has_one_positive(self) -> None:
        definition_names = [entry["$ref"].rsplit("/", 1)[1] for entry in self.schema["oneOf"]]
        record_kinds = {
            self.schema["$defs"][name]["properties"]["record_kind"]["const"]
            for name in definition_names
        }
        positive_kinds = [vector["record_kind"] for vector in self.vectors["positives"]]
        self.assertEqual(set(positive_kinds), record_kinds)
        self.assertEqual(len(positive_kinds), len(set(positive_kinds)))
        self.assertEqual(self.manifest["counts"]["top_level_record_kinds"], len(record_kinds))

    def test_schema_stage_positive_vectors(self) -> None:
        for vector in self.vectors["positives"]:
            with self.subTest(vector=vector["id"]):
                self.assertEqual(vector["expected"], {
                    "verdict": "ACCEPT",
                    "stage": "SCHEMA",
                    "code": "VALID",
                })
                errors = self.validator.errors(vector["instance"], fail_fast=True)
                self.assertEqual(errors, [])

    def test_schema_stage_negative_vectors(self) -> None:
        vectors = [
            vector for vector in self.vectors["negatives"]
            if vector["expected"]["stage"] == "SCHEMA"
        ]
        self.assertEqual(len(vectors), self.manifest["counts"]["schema_negative"])
        for vector in vectors:
            with self.subTest(vector=vector["id"]):
                self.assertEqual(vector["expected"]["verdict"], "REJECT")
                self.assertEqual(vector["expected"]["code"], "SCHEMA_INVALID")
                self.assertTrue(self.validator.errors(vector["instance"], fail_fast=True))

    def test_runtime_negative_metadata_is_exhaustive_not_a_pass(self) -> None:
        vectors = [
            vector for vector in self.vectors["negatives"]
            if vector["expected"]["stage"] != "SCHEMA"
        ]
        self.assertEqual(len(vectors), self.manifest["counts"]["runtime_negative"])
        covered = {vector["category"] for vector in self.vectors["negatives"]}
        self.assertEqual(set(self.vectors["required_negative_categories"]), covered)
        for vector in vectors:
            with self.subTest(vector=vector["id"]):
                self.assertEqual(vector["expected"]["verdict"], "REJECT")
                self.assertNotEqual(vector["expected"]["code"], "VALID")
                self.assertRegex(vector["expected"]["stage"], r"^[A-Z][A-Z0-9_]*$")
                self.assertRegex(vector["expected"]["code"], r"^[A-Z][A-Z0-9_]*$")
                self.assertEqual(self.validator.errors(vector["instance"], fail_fast=True), [])
                self.assertIn("context", vector)

    def test_positive_ed25519_signatures_are_real_and_domain_bound(self) -> None:
        verified = 0
        fixture_key = bytes.fromhex(self.vectors["fixture_public_key_ed25519"])
        for vector in self.vectors["positives"]:
            for record in signed_records(vector["instance"]):
                signature = record["signature"]
                unsigned = dict(record)
                del unsigned["signature"]
                message = signature["domain"].encode("utf-8") + canonical_bytes(unsigned)
                self.assertEqual(bytes.fromhex(signature["public_key"]), fixture_key)
                self.assertTrue(
                    ed25519_verify(
                        bytes.fromhex(signature["public_key"]),
                        bytes.fromhex(signature["signature"]),
                        message,
                    ),
                    vector["id"],
                )
                tampered_domain = b"NOOS/SIG/WRONG-DOMAIN/V1" + canonical_bytes(unsigned)
                self.assertFalse(
                    ed25519_verify(
                        bytes.fromhex(signature["public_key"]),
                        bytes.fromhex(signature["signature"]),
                        tampered_domain,
                    )
                )
                verified += 1
        self.assertEqual(verified, 7)


if __name__ == "__main__":
    unittest.main()
