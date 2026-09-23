"""DBGuardAI spec engine - validation and evaluation of control specs."""

from .records import RecordsIndex, RecordsIntegrityError
from .specs import load_spec, spec_sha256
from .validate import validate_spec
from .manifest import build_manifest, main as build_manifest_main

__all__ = [
    "RecordsIndex",
    "RecordsIntegrityError",
    "load_spec",
    "spec_sha256",
    "validate_spec",
    "build_manifest",
    "build_manifest_main",
]
