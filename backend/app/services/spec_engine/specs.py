"""Spec loading and hashing utilities."""

import hashlib
import json
from pathlib import Path

import yaml


class DuplicateKeyLoader(yaml.SafeLoader):
    """YAML loader that raises an error on duplicate keys."""
    pass


def construct_mapping(loader, node):
    """Construct mapping with duplicate key detection."""
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in mapping:
            raise yaml.YAMLError(f"Duplicate key: {key}")
        value = loader.construct_object(value_node, deep=False)
        mapping[key] = value
    return mapping


DuplicateKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_mapping
)


def load_spec(path: Path) -> dict:
    """Load a spec from YAML file with duplicate key rejection."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    # Use custom loader that rejects duplicate keys
    return yaml.load(content, Loader=DuplicateKeyLoader)


def spec_sha256(spec: dict) -> str:
    """Compute canonical-JSON SHA-256 hash of a spec."""
    sha_str = json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(sha_str.encode("utf-8")).hexdigest()
