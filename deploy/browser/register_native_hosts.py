#!/usr/bin/env python3
"""Register public machine native-messaging manifests without exposing agent state."""
import json
import os
from pathlib import Path
import re
import stat
import uuid

CHROMIUM = (
    "etc/opt/chrome/native-messaging-hosts", "etc/chromium/native-messaging-hosts",
    "etc/opt/edge/native-messaging-hosts", "etc/opt/brave/native-messaging-hosts",
)
FIREFOX = ("usr/lib/mozilla/native-messaging-hosts", "usr/lib64/mozilla/native-messaging-hosts")
MANAGED = ("usr/lib/mozilla/managed-storage", "usr/lib64/mozilla/managed-storage")
NAME = "app.milvago.browser.json"


def _directory(root, relative, *, preserve_existing=False):
    """Retain directory handles throughout; never follow links or writable parents."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("Unprotected native-messaging root")
        parts = relative.split("/")
        for index, part in enumerate(parts):
            created = False
            try:
                os.mkdir(part, 0o755, dir_fd=fd)
                created = True
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                info = os.fstat(child)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise PermissionError("Unprotected native-messaging ancestor")
                if created or (index == len(parts) - 1 and not preserve_existing):
                    os.fchmod(child, 0o755)
                elif not info.st_mode & 0o001:
                    raise PermissionError("Native-messaging ancestor is not traversable")
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write(directory, value):
    try:
        previous = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        previous = None
    if previous is not None:
        try:
            info = os.fstat(previous)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 4096:
                raise PermissionError("Unprotected native-messaging manifest")
        finally:
            os.close(previous)
    temporary = ".milvago-native-" + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(json.dumps(value, ensure_ascii=True).encode("ascii"))
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, NAME, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def _existing_managed(directory, firefox):
    fd = os.open(firefox + ".json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != 0 or before.st_mode & 0o022 or not before.st_mode & 0o004 or before.st_size > 65536:
            raise PermissionError("Unprotected Firefox managed configuration")
        data = os.read(fd, 65537)
        after = os.fstat(fd)
        if len(data) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise PermissionError("Firefox managed configuration changed")
        value = json.loads(data)
        if not isinstance(value, dict) or set(value) - {"name", "description", "type", "data"} or value.get("name") != firefox or value.get("type") != "storage" or not isinstance(value.get("data"), dict):
            raise ValueError("Invalid Firefox managed configuration")
        description = value.get("description")
        if not isinstance(description, str) or not description or len(description) > 1024 or any(ord(character) < 32 for character in description):
            raise ValueError("Invalid Firefox managed description")
    finally:
        os.close(fd)


def _managed(directory, firefox):
    # Firefox rejects storage.managed.get() when no manifest exists. An empty
    # machine manifest represents the native Linux protocol without inventing
    # a broker pin. Never replace an administrator's configured authority.
    try:
        _existing_managed(directory, firefox)
        return
    except FileNotFoundError:
        pass
    temporary = ".milvago-managed-" + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(json.dumps({"name": firefox, "description": "Milvago browser configuration",
                                     "type": "storage", "data": {}}).encode("ascii"))
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        try:
            os.link(temporary, firefox + ".json", src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        except FileExistsError:
            _existing_managed(directory, firefox)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def register(chromium, firefox, binary, *, root=Path("/")):
    if os.geteuid() != 0:
        raise PermissionError("Root is required")
    if not isinstance(chromium, str) or not isinstance(firefox, str) or len(firefox) > 100 or not re.fullmatch(r"[a-p]{32}", chromium) or not re.fullmatch(r"[a-z0-9.-]+@milvago\.app", firefox):
        raise ValueError("Invalid browser extension identity")
    if binary not in (
        "/opt/milvago-browser/milvago-browser-agent",
        "/opt/milvago-commercial/milvago-commercial-bridge",
    ):
        raise ValueError("Unexpected native-messaging image")
    root = Path(root)
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("Canonical root is required")
    image_directory = _directory(root, str(Path(binary).parent).lstrip("/"))
    try:
        image = os.open(Path(binary).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=image_directory)
        try:
            info = os.fstat(image)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o111:
                raise PermissionError("Unprotected native-messaging image")
        finally:
            os.close(image)
    finally:
        os.close(image_directory)
    manifest = {"name": "app.milvago.browser", "description": "Milvago browser policy bridge",
                "path": binary, "type": "stdio", "allowed_origins": [f"chrome-extension://{chromium}/"]}
    gecko = dict(manifest)
    del gecko["allowed_origins"]
    gecko["allowed_extensions"] = [firefox]
    for relative, document in [(name, manifest) for name in CHROMIUM] + [(name, gecko) for name in FIREFOX]:
        directory = _directory(root, relative, preserve_existing=True)
        try:
            _write(directory, document)
        finally:
            os.close(directory)
    for relative in MANAGED:
        directory = _directory(root, relative, preserve_existing=True)
        try:
            _managed(directory, firefox)
        finally:
            os.close(directory)
