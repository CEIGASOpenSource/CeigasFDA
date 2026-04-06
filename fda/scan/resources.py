"""System resource detection.

CPU cores, RAM, GPU — so the entity understands the machine's
capacity before proposing automation workloads.
"""

import os
import platform
import subprocess


def scan_resources() -> dict:
    """Gather CPU, RAM, and GPU information."""
    system = platform.system()
    info = {
        "cpu_cores": os.cpu_count() or 0,
        "ram_gb": 0,
        "gpu": "unknown",
    }

    if system == "Darwin":
        info.update(_scan_resources_macos())
    elif system == "Windows":
        info.update(_scan_resources_windows())
    else:
        info["ram_gb"] = _get_ram_linux()

    return info


def _scan_resources_macos() -> dict:
    """macOS-specific resource detection."""
    info = {}

    # CPU info
    try:
        result = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"],
            capture_output=True, text=True, timeout=5,
        )
        cpu_brand = result.stdout.strip()
        if cpu_brand:
            info["cpu_model"] = cpu_brand
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Apple Silicon chip name
    try:
        result = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"],
            capture_output=True, text=True, timeout=5,
        )
        brand = result.stdout.strip()
        if "Apple" in brand:
            info["cpu_model"] = brand
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # RAM
    try:
        result = subprocess.run(
            ["sysctl", "-n", "hw.memsize"],
            capture_output=True, text=True, timeout=5,
        )
        mem_bytes = int(result.stdout.strip())
        info["ram_gb"] = round(mem_bytes / (1024**3), 1)
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass

    # GPU (system_profiler)
    try:
        result = subprocess.run(
            ["system_profiler", "SPDisplaysDataType", "-json"],
            capture_output=True, text=True, timeout=10,
        )
        import json
        data = json.loads(result.stdout)
        displays = data.get("SPDisplaysDataType", [])
        if displays:
            gpu = displays[0]
            gpu_name = gpu.get("sppci_model", gpu.get("_name", "unknown"))
            vram = gpu.get("sppci_vram", "")
            info["gpu"] = gpu_name
            if vram:
                info["gpu_vram"] = vram
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError, KeyError):
        pass

    return info


def _scan_resources_windows() -> dict:
    """Windows-specific resource detection."""
    info = {}

    # CPU model
    try:
        result = subprocess.run(
            ["wmic", "cpu", "get", "Name", "/value"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if line.startswith("Name="):
                info["cpu_model"] = line.split("=", 1)[1].strip()
                break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # RAM
    try:
        result = subprocess.run(
            ["wmic", "computersystem", "get", "TotalPhysicalMemory", "/value"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if line.startswith("TotalPhysicalMemory="):
                mem_bytes = int(line.split("=", 1)[1].strip())
                info["ram_gb"] = round(mem_bytes / (1024**3), 1)
                break
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass

    # GPU
    try:
        result = subprocess.run(
            ["wmic", "path", "win32_VideoController", "get", "Name", "/value"],
            capture_output=True, text=True, timeout=10,
        )
        gpus = []
        for line in result.stdout.splitlines():
            if line.startswith("Name="):
                gpus.append(line.split("=", 1)[1].strip())
        if gpus:
            info["gpu"] = gpus[0]
            if len(gpus) > 1:
                info["gpu_secondary"] = gpus[1]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return info


def _get_ram_linux() -> float:
    """Fallback RAM detection for Linux."""
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return round(kb / (1024**2), 1)
    except (FileNotFoundError, ValueError):
        pass
    return 0
