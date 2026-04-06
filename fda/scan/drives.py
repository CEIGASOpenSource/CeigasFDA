"""Drive and volume mapping.

Maps mounted volumes with filesystem type, total capacity, and free space.
Does NOT read file contents — only filesystem metadata.
"""

import os
import platform
import shutil
import subprocess


def scan_drives() -> list[dict]:
    """Return list of mounted volumes with space information."""
    system = platform.system()
    if system == "Darwin":
        return _scan_drives_macos()
    elif system == "Windows":
        return _scan_drives_windows()
    return _scan_drives_fallback()


def _scan_drives_macos() -> list[dict]:
    """Map volumes on macOS using diskutil."""
    volumes = []

    try:
        result = subprocess.run(
            ["df", "-h"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            mount = parts[-1]
            # Skip system/internal volumes
            if mount.startswith("/System") or mount.startswith("/private"):
                continue
            if mount in ("/", "/Volumes") or mount.startswith("/Volumes/"):
                usage = shutil.disk_usage(mount)
                volumes.append({
                    "mount": mount,
                    "filesystem": _get_fs_type_macos(mount),
                    "total_gb": round(usage.total / (1024**3), 1),
                    "free_gb": round(usage.free / (1024**3), 1),
                    "used_percent": round((usage.used / usage.total) * 100, 1) if usage.total else 0,
                })
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # Fallback to just root
        volumes = _scan_drives_fallback()

    # Always ensure root is included
    if not any(v["mount"] == "/" for v in volumes):
        try:
            usage = shutil.disk_usage("/")
            volumes.insert(0, {
                "mount": "/",
                "filesystem": _get_fs_type_macos("/"),
                "total_gb": round(usage.total / (1024**3), 1),
                "free_gb": round(usage.free / (1024**3), 1),
                "used_percent": round((usage.used / usage.total) * 100, 1),
            })
        except OSError:
            pass

    return volumes


def _get_fs_type_macos(mount: str) -> str:
    """Get filesystem type for a mount point on macOS."""
    try:
        result = subprocess.run(
            ["diskutil", "info", mount],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "File System Personality" in line or "Type (Bundle)" in line:
                return line.split(":", 1)[1].strip().lower()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return "unknown"


def _scan_drives_windows() -> list[dict]:
    """Map volumes on Windows."""
    volumes = []

    try:
        # Use wmic to get logical disk info
        result = subprocess.run(
            ["wmic", "logicaldisk", "get",
             "DeviceID,FileSystem,Size,FreeSpace,DriveType",
             "/format:csv"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.strip().splitlines():
            if not line.strip() or "Node" in line:
                continue
            parts = line.strip().split(",")
            if len(parts) < 5:
                continue
            # CSV: Node,DeviceID,DriveType,FileSystem,FreeSpace,Size
            try:
                device_id = parts[1]
                drive_type = parts[2]
                filesystem = parts[3]
                free_space = int(parts[4]) if parts[4] else 0
                total_size = int(parts[5]) if parts[5] else 0
            except (IndexError, ValueError):
                continue

            # Only local fixed disks (type 3) and removable (type 2)
            if drive_type not in ("2", "3"):
                continue

            volumes.append({
                "mount": device_id,
                "filesystem": filesystem.lower() if filesystem else "unknown",
                "total_gb": round(total_size / (1024**3), 1) if total_size else 0,
                "free_gb": round(free_space / (1024**3), 1) if free_space else 0,
                "used_percent": round(((total_size - free_space) / total_size) * 100, 1) if total_size else 0,
            })
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        volumes = _scan_drives_fallback()

    return volumes


def _scan_drives_fallback() -> list[dict]:
    """Fallback: use shutil for basic disk info."""
    volumes = []
    paths = ["/"] if platform.system() != "Windows" else ["C:\\"]
    for path in paths:
        try:
            usage = shutil.disk_usage(path)
            volumes.append({
                "mount": path,
                "filesystem": "unknown",
                "total_gb": round(usage.total / (1024**3), 1),
                "free_gb": round(usage.free / (1024**3), 1),
                "used_percent": round((usage.used / usage.total) * 100, 1),
            })
        except OSError:
            pass
    return volumes
