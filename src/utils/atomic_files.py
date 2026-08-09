"""Small atomic file-write helpers for runtime artifacts.

All temporary files are created beside the destination so ``os.replace``
stays on the same filesystem.  Readers therefore observe either the old
complete file or the new complete file, never a partially written artifact.
"""

import json
import os
import shutil
import tempfile
from typing import Any

import numpy as np


def _temporary_path(path: str) -> tuple[int, str]:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    return tempfile.mkstemp(prefix=".%s." % os.path.basename(path), suffix=".tmp", dir=directory)


def atomic_write_json(path: str, data: Any, *, ensure_ascii: bool = False, indent: int = 2) -> None:
    fd, temp_path = _temporary_path(path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=ensure_ascii, indent=indent)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def atomic_write_bytes(path: str, data: bytes) -> None:
    fd, temp_path = _temporary_path(path)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def atomic_save_npy(path: str, array: np.ndarray) -> None:
    fd, temp_path = _temporary_path(path)
    try:
        with os.fdopen(fd, "wb") as stream:
            np.save(stream, array)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def atomic_copy_file(source: str, destination: str) -> None:
    fd, temp_path = _temporary_path(destination)
    os.close(fd)
    try:
        shutil.copy2(source, temp_path)
        os.replace(temp_path, destination)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise
