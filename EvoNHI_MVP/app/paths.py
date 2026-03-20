from __future__ import annotations

from pathlib import Path

from app.config import settings


def _candidate_path(raw_path: str | Path) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    return (settings.manifest_root / path).resolve()


def _assert_inside_manifest_root(resolved: Path) -> Path:
    root = settings.manifest_root.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"Manifest path {resolved} must stay inside the configured manifest root {root}"
        ) from exc
    return resolved


def normalize_manifest_path(raw_path: str | Path) -> str:
    resolved = _assert_inside_manifest_root(_candidate_path(raw_path))
    if not resolved.exists():
        raise ValueError(f"Manifest path does not exist: {resolved}")
    if not resolved.is_dir():
        raise ValueError(f"Manifest path must point to a directory of YAML manifests: {resolved}")
    return resolved.relative_to(settings.manifest_root.resolve()).as_posix()


def resolve_manifest_path(stored_path: str | Path) -> Path:
    resolved = _assert_inside_manifest_root(_candidate_path(stored_path))
    if not resolved.exists():
        raise ValueError(f"Manifest path does not exist: {resolved}")
    if not resolved.is_dir():
        raise ValueError(f"Manifest path must point to a directory of YAML manifests: {resolved}")
    return resolved
