"""SHA-256 snapshots of the paths configured for file integrity monitoring."""
from __future__ import annotations
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
CHUNK_SIZE = 65536
_HASH_KEY = "sha256"
_INODE_KEY = "inode"
_DEVICE_KEY = "device"
@dataclass(frozen=True)
class FileRecord:
    """Content hash plus identity used to recognize a rename."""
    sha256: str
    inode: int | None
    device: int | None
def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a regular file or a symlink target path.
    Symlinks are hashed from the link text. The monitor does not follow them,
    so a link cannot pull an unrelated file into the baseline.
    """
    digest = hashlib.sha256()
    if path.is_symlink():
        digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
        return digest.hexdigest()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()
def snapshot(
    paths: list[Path],
    retain: dict[str, FileRecord] | None = None,
    exclude: set[Path] | None = None,
) -> tuple[dict[str, FileRecord], list[str]]:
    """Hash every monitored file.
    Unreadable files that are already in ``retain`` keep their previous record
    so a permission error is not reported as deletion. Missing configured
    paths are skipped until they exist.
    """
    retained = retain or {}
    excluded = {_normalize(path) for path in (exclude or set())}
    records: dict[str, FileRecord] = {}
    warnings: list[str] = []
    for root in paths:
        if not root.exists() and not root.is_symlink():
            continue
        for file_path in _iter_files(root, warnings):
            key = str(file_path)
            if _normalize(file_path) in excluded:
                continue
            try:
                records[key] = _record_for(file_path)
            except (OSError, PermissionError) as exc:
                if key in retained:
                    records[key] = retained[key]
                    warnings.append(f"kept previous hash for unreadable file {key}: {exc}")
                else:
                    warnings.append(f"skipped unreadable file {key}: {exc}")
    return records, warnings
def records_to_json(records: dict[str, FileRecord]) -> dict[str, dict[str, str | int | None]]:
    return {
        path: {
            _HASH_KEY: record.sha256,
            _INODE_KEY: record.inode,
            _DEVICE_KEY: record.device,
        }
        for path, record in records.items()
    }
def records_from_json(payload: dict) -> dict[str, FileRecord]:
    records: dict[str, FileRecord] = {}
    for path, raw in payload.items():
        if not isinstance(raw, dict) or not isinstance(raw.get(_HASH_KEY), str):
            continue
        inode = raw.get(_INODE_KEY)
        device = raw.get(_DEVICE_KEY)
        records[str(path)] = FileRecord(
            sha256=raw[_HASH_KEY],
            inode=inode if isinstance(inode, int) else None,
            device=device if isinstance(device, int) else None,
        )
    return records
def _record_for(path: Path) -> FileRecord:
    info = path.stat(follow_symlinks=False)
    if not path.is_symlink() and not stat.S_ISREG(info.st_mode):
        raise OSError(f"not a regular file: {path}")
    inode = int(info.st_ino)
    device = int(info.st_dev)
    # Windows reports 0 when the platform cannot supply a stable inode.
    if inode <= 0:
        inode = None
        device = None
    return FileRecord(sha256=sha256_file(path), inode=inode, device=device)
def _iter_files(root: Path, warnings: list[str]):
    if root.is_symlink() or root.is_file():
        yield root
        return
    if not root.is_dir():
        warnings.append(f"skipped unsupported path {root}")
        return
    def _on_error(error: OSError) -> None:
        warnings.append(f"skipped unreadable directory {error.filename}: {error}")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=_on_error):
        current = Path(dirpath)
        dirnames[:] = sorted(
            name for name in dirnames if not (current / name).is_symlink()
        )
        for name in sorted(filenames):
            yield current / name
def _normalize(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))
