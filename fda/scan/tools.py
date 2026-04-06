"""Installed tools detection.

Detects developer tools, package managers, and runtimes available
on the system. The entity uses this to know what it can leverage
for automation without installing anything new.
"""

import platform
import shutil
import subprocess


def scan_tools() -> dict:
    """Detect installed tools and their versions."""
    tools = {}

    # Developer tools — check presence and version
    tool_checks = {
        "git": ["git", "--version"],
        "python": ["python3", "--version"],
        "node": ["node", "--version"],
        "npm": ["npm", "--version"],
        "docker": ["docker", "--version"],
        "cargo": ["cargo", "--version"],
        "go": ["go", "version"],
        "java": ["java", "--version"],
        "ruby": ["ruby", "--version"],
        "php": ["php", "--version"],
    }

    for tool_name, cmd in tool_checks.items():
        version = _get_tool_version(cmd)
        if version:
            tools[tool_name] = version

    # Platform-specific package managers
    system = platform.system()
    if system == "Darwin":
        for name, cmd in [
            ("brew", ["brew", "--version"]),
            ("xcode_cli", ["xcode-select", "-p"]),
        ]:
            version = _get_tool_version(cmd)
            if version:
                tools[name] = version if name != "xcode_cli" else True

    elif system == "Windows":
        for name, cmd in [
            ("choco", ["choco", "--version"]),
            ("winget", ["winget", "--version"]),
            ("scoop", ["scoop", "--version"]),
            ("wsl", ["wsl", "--status"]),
        ]:
            version = _get_tool_version(cmd)
            if version:
                tools[name] = version if name != "wsl" else True

    # Editors/IDEs (presence only, no version)
    editor_checks = _detect_editors()
    if editor_checks:
        tools["editors"] = editor_checks

    return tools


def _get_tool_version(cmd: list[str]) -> str | None:
    """Run a version command and extract the version string."""
    if not shutil.which(cmd[0]):
        return None

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=5,
        )
        output = (result.stdout + result.stderr).strip()
        if not output:
            return None

        # Extract version number from common formats
        # "git version 2.43.0" → "2.43.0"
        # "v20.11.0" → "20.11.0"
        # "Python 3.12.1" → "3.12.1"
        import re
        version_match = re.search(r'(\d+\.\d+[\.\d]*)', output)
        if version_match:
            return version_match.group(1)

        # Fallback: return first line truncated
        return output.splitlines()[0][:50]

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _detect_editors() -> list[str]:
    """Detect installed code editors/IDEs."""
    editors = []
    system = platform.system()

    if system == "Darwin":
        editor_paths = {
            "vscode": "/Applications/Visual Studio Code.app",
            "cursor": "/Applications/Cursor.app",
            "sublime": "/Applications/Sublime Text.app",
            "intellij": "/Applications/IntelliJ IDEA.app",
            "xcode": "/Applications/Xcode.app",
            "pycharm": "/Applications/PyCharm.app",
            "webstorm": "/Applications/WebStorm.app",
        }
        import os
        for name, path in editor_paths.items():
            if os.path.exists(path):
                editors.append(name)

        # Also check CLI tools
        if shutil.which("code"):
            if "vscode" not in editors:
                editors.append("vscode")

    elif system == "Windows":
        import os
        # Common install locations
        program_files = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        local_apps = os.environ.get("LOCALAPPDATA", "")

        editor_paths = {
            "vscode": os.path.join(local_apps, "Programs", "Microsoft VS Code"),
            "cursor": os.path.join(local_apps, "Programs", "Cursor"),
            "sublime": os.path.join(program_files, "Sublime Text"),
            "notepadpp": os.path.join(program_files, "Notepad++"),
        }
        for name, path in editor_paths.items():
            if os.path.isdir(path):
                editors.append(name)

    return editors
