from __future__ import annotations

import hashlib
import math
from pathlib import Path

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".jar", ".msi", ".hta"}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def analyze_file_bytes(filename: str, content_type: str | None, data: bytes) -> dict:
    if len(data) > 10 * 1024 * 1024:
        raise ValueError("File is larger than the 10 MB local analysis limit.")
    ext = Path(filename or "").suffix.lower()
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()  # compatibility fingerprint only, not security use
    entropy = _entropy(data)

    indicators = []
    score = 0
    if ext in SUSPICIOUS_EXTENSIONS:
        score += 35
        indicators.append(f"Executable or script-like extension detected: {ext}")
    if entropy > 7.5 and len(data) > 4096:
        score += 20
        indicators.append("High byte entropy may indicate compression, encryption, or packed content.")
    if data.startswith(b"MZ"):
        score += 25
        indicators.append("Windows PE executable signature detected.")
    if b"powershell" in data[:250000].lower() or b"cmd.exe" in data[:250000].lower():
        score += 15
        indicators.append("Command-shell keywords found in the file sample.")

    score = min(score, 100)
    risk = "low" if score < 30 else "medium" if score < 60 else "high"
    if not indicators:
        indicators.append("No obvious local static indicators were detected.")

    return {
        "filename": filename,
        "content_type": content_type,
        "size_bytes": len(data),
        "extension": ext or "none",
        "sha256": sha256,
        "md5": md5,
        "entropy": entropy,
        "risk_score": score,
        "risk": risk,
        "indicators": indicators,
        "note": "This is a local static check. The file is not executed and this does not replace antivirus or malware sandboxing.",
    }
