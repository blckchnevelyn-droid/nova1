"""Descriptor-relative sandbox for the Nova file-write pilot (POSIX only).

All filesystem access goes through a trusted root directory descriptor. Each
path component is opened with O_NOFOLLOW relative to its parent descriptor, so
a symlink anywhere on the path is refused at open time rather than checked
beforehand. Publication uses link(2), which never replaces an existing target.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from typing import Callable, Optional

if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
    raise ImportError("the file-write pilot requires a POSIX platform with O_NOFOLLOW and O_DIRECTORY")

MAX_BYTES = 1 << 20
_OPERATION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_STAGE_PREFIX = ".nova-stage-"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW

Hook = Optional[Callable[[str], None]]


class SandboxError(ValueError):
    """Refused before any file effect: bad path, missing parent, or unsafe parent."""


class SandboxConflict(SandboxError):
    """Target exists, is not a regular file, or cannot be opened safely. Never overwritten."""


class PublishAfterLink(SandboxError):
    """The target was linked into place, then a later step failed. The effect exists."""


# Advisory capability: only the pilot module imports this sentinel. It prevents accidental
# direct use of the publish path. It is not a security boundary against code that deliberately
# imports it; that protection comes from the kernel's audit and evidence chain.
PILOT_PUBLISH_CAPABILITY = object()


@dataclass(frozen=True)
class Observation:
    sha256: str
    length: int


def expected_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def normalize_relative_path(raw: object) -> tuple[str, ...]:
    """Validate a sandbox-relative path and return its components. No filesystem access."""
    if not isinstance(raw, str) or raw == "":
        raise SandboxError("path must be a non-empty string")
    if "\x00" in raw:
        raise SandboxError("path contains a NUL byte")
    if "\\" in raw:
        raise SandboxError("backslashes are not permitted in sandbox paths")
    if raw.startswith("/"):
        raise SandboxError("absolute paths are not permitted")
    parts = tuple(raw.split("/"))
    for part in parts:
        if part in ("", ".", ".."):
            raise SandboxError("path contains an empty, '.', or '..' component")
        if part.startswith(_STAGE_PREFIX):
            raise SandboxError("path uses the reserved staging prefix")
    return parts


class SandboxRoot:
    """Trusted handle for one sandbox root. The root path itself must not be a symlink."""

    def __init__(self, path: str) -> None:
        if not os.path.isabs(path):
            raise SandboxError("sandbox root must be an absolute path")
        self._root_fd: Optional[int] = os.open(path, _DIR_FLAGS)

    def close(self) -> None:
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def __enter__(self) -> "SandboxRoot":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _open_parent(self, parts: tuple[str, ...]) -> int:
        if self._root_fd is None:
            raise SandboxError("sandbox root is closed")
        fd = os.dup(self._root_fd)
        try:
            for name in parts[:-1]:
                nxt = os.open(name, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = nxt
            return fd
        except OSError as exc:
            os.close(fd)
            raise SandboxError("parent directory is missing, not a directory, or a symlink") from exc

    def observe(self, parts: tuple[str, ...]) -> Optional[Observation]:
        """Hash the target without following symlinks. None means the target is absent."""
        dfd = self._open_parent(parts)
        try:
            return _observe_at(dfd, parts[-1])
        finally:
            os.close(dfd)

    def publish(self, relative_path: str, content: bytes, *, operation_id: str, hook: Hook = None,
                capability: object = None) -> None:
        """Stage exact bytes under an operation-bound name, then publish without replacement.

        Failures before the link raise SandboxError/OSError with no effect. Failures after the
        link raise PublishAfterLink, because the caller must then treat the effect as possible.
        """
        if capability is not PILOT_PUBLISH_CAPABILITY:
            raise SandboxError("publish is reserved for the governed file-write pilot")
        parts = normalize_relative_path(relative_path)
        if not _OPERATION_ID.match(operation_id):
            raise SandboxError("operation id is not a canonical UUID")
        if len(content) > MAX_BYTES:
            raise SandboxError("content exceeds pilot size limit")
        stage = _stage_name(operation_id)
        dfd = self._open_parent(parts)
        try:
            target = parts[-1]
            _unlink_if_present(stage, dfd)  # stale staging from an earlier crash; name is operation-bound
            _call(hook, "stage_begin")
            fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd)
            try:
                _write_all(fd, content)
                os.fsync(fd)
            finally:
                os.close(fd)
            _call(hook, "after_stage")
            _call(hook, "before_publish")
            try:
                os.link(stage, target, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
            except FileExistsError as exc:
                raise SandboxConflict("target already exists; not overwritten") from exc
            try:
                _call(hook, "after_publish")
                os.fsync(dfd)
                os.unlink(stage, dir_fd=dfd)
                os.fsync(dfd)
            except (OSError, SandboxError) as exc:
                raise PublishAfterLink(f"publication completed but finalization failed: {exc}") from exc
        finally:
            os.close(dfd)

    def discard_stage(self, relative_path: str, operation_id: str) -> None:
        """Remove this operation's staging file if present. Safe to call repeatedly."""
        parts = normalize_relative_path(relative_path)
        dfd = self._open_parent(parts)
        try:
            _unlink_if_present(_stage_name(operation_id), dfd)
            os.fsync(dfd)
        finally:
            os.close(dfd)


def _stage_name(operation_id: str) -> str:
    return f"{_STAGE_PREFIX}{operation_id}"


def _observe_at(dfd: int, name: str) -> Optional[Observation]:
    try:
        fd = os.open(name, _READ_FLAGS, dir_fd=dfd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SandboxConflict("target is a symlink or cannot be opened safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SandboxConflict("target is not a regular file")
        if info.st_size > MAX_BYTES:
            raise SandboxConflict("target exceeds pilot size limit")
        data = _read_all(fd)
    finally:
        os.close(fd)
    return Observation(hashlib.sha256(data).hexdigest(), len(data))


def _unlink_if_present(name: str, dfd: int) -> None:
    try:
        os.unlink(name, dir_fd=dfd)
    except FileNotFoundError:
        pass


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _read_all(fd: int) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_BYTES:
            raise SandboxConflict("target exceeds pilot size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _call(hook: Hook, point: str) -> None:
    if hook is not None:
        hook(point)
