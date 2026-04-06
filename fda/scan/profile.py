"""User profile structure mapping.

Maps the user's home directory structure — which standard directories
exist, approximate file counts. Does NOT read file contents.
"""

import os
import platform


def scan_profile() -> dict:
    """Map user profile directory structure."""
    home = os.path.expanduser("~")
    system = platform.system()

    info = {
        "home": home,
    }

    # Standard user directories (cross-platform names)
    if system == "Darwin":
        check_dirs = {
            "documents": os.path.join(home, "Documents"),
            "downloads": os.path.join(home, "Downloads"),
            "desktop": os.path.join(home, "Desktop"),
            "pictures": os.path.join(home, "Pictures"),
            "music": os.path.join(home, "Music"),
            "movies": os.path.join(home, "Movies"),
        }
    elif system == "Windows":
        check_dirs = {
            "documents": os.path.join(home, "Documents"),
            "downloads": os.path.join(home, "Downloads"),
            "desktop": os.path.join(home, "Desktop"),
            "pictures": os.path.join(home, "Pictures"),
            "music": os.path.join(home, "Music"),
            "videos": os.path.join(home, "Videos"),
        }
    else:
        check_dirs = {
            "documents": os.path.join(home, "Documents"),
            "downloads": os.path.join(home, "Downloads"),
            "desktop": os.path.join(home, "Desktop"),
        }

    for name, path in check_dirs.items():
        info[name] = os.path.isdir(path)

    # Estimate total file count in home directory (top 2 levels only)
    # This gives the entity a sense of scale without deep traversal
    info["estimated_files"] = _estimate_file_count(home, max_depth=2)

    return info


def _estimate_file_count(root: str, max_depth: int = 2) -> int:
    """Estimate file count in a directory tree, limited depth.

    Skips hidden directories and known large/irrelevant trees
    to keep the scan fast and non-invasive.
    """
    skip_dirs = {
        # System/cache directories that inflate count without meaning
        "Library", "AppData", ".Trash", ".cache", ".local",
        "node_modules", "__pycache__", ".git", ".venv",
        "venv", ".npm", ".cargo", ".rustup",
    }

    count = 0
    try:
        for entry in os.scandir(root):
            if entry.name.startswith(".") and entry.name not in (".config",):
                continue
            if entry.is_file(follow_symlinks=False):
                count += 1
            elif entry.is_dir(follow_symlinks=False) and max_depth > 1:
                if entry.name in skip_dirs:
                    continue
                try:
                    count += _estimate_file_count(entry.path, max_depth - 1)
                except PermissionError:
                    pass
    except PermissionError:
        pass

    return count
