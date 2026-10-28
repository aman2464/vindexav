import math
from pathlib import Path
from typing import Dict, Any, List
from collections import Counter
from config import cfg

# Attempt pefile import for Windows binaries (silent fallback if not on system)
try:
    import pefile
except ImportError:
    pefile = None


class HeuristicEngine:
    """Calculates byte distribution entropy, checks magic bytes, and inspects PE structures."""

    def __init__(self):
        self.entropy_cutoff = getattr(cfg, "entropy_cutoff", 7.2)
        self.scores = getattr(cfg, "scores", {
            "high_entropy": 30,
            "double_extension": 20,
            "pe_anomaly": 35,
            "magic_mismatch": 25
        })

    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        occurences = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in occurences.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return round(entropy, 4)

    def inspect(self, file_path: str) -> Dict[str, Any]:
        p = Path(file_path)
        reasons: List[str] = []
        score = 0

        if not p.is_file():
            return {"score": 0, "reasons": reasons, "entropy": 0.0}

        # 1. Double extension check (e.g. invoice.pdf.exe)
        name_lower = p.name.lower()
        suspicious_exts = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".sh"}
        doc_exts = {".pdf", ".docx", ".xlsx", ".txt", ".jpg", ".png", ".zip"}
        parts = name_lower.split(".")
        if len(parts) > 2:
            prev_ext = f".{parts[-2]}"
            last_ext = f".{parts[-1]}"
            if prev_ext in doc_exts and last_ext in suspicious_exts:
                score += self.scores.get("double_extension", 20)
                reasons.append(f"Deceptive double extension detected ({prev_ext}{last_ext})")

        # 2. Entropy and header inspection
        try:
            with open(p, "rb") as f:
                header = f.read(4096)
                f.seek(0)
                full_bytes = f.read(1024 * 1024 * 5) # Sample up to 5MB

            entropy = self.calculate_entropy(full_bytes)
            if entropy >= self.entropy_cutoff:
                score += self.scores.get("high_entropy", 30)
                reasons.append(f"High Shannon entropy ({entropy} >= {self.entropy_cutoff})")

            # 3. Header vs Extension mismatch check
            ext = p.suffix.lower()
            if ext in [".png", ".jpg", ".jpeg", ".pdf", ".txt"]:
                # Check for Windows MZ or Linux ELF magic bytes masquerading as documents
                if header.startswith(b"MZ") or header.startswith(b"\x7fELF"):
                    score += self.scores.get("magic_mismatch", 25)
                    reasons.append(f"Header magic mismatch: executable format inside {ext} extension")

            # 4. Optional PE anomaly check
            if pefile and header.startswith(b"MZ"):
                try:
                    pe = pefile.PE(data=full_bytes, fast_load=True)
                    for section in pe.sections:
                        flags = section.Characteristics
                        # Check for Section with both IMAGE_SCN_MEM_EXECUTE (0x20000000) and IMAGE_SCN_MEM_WRITE (0x80000000)
                        if (flags & 0x20000000) and (flags & 0x80000000):
                            score += self.scores.get("pe_anomaly", 35)
                            reasons.append(f"Suspicious PE section {section.Name.decode(errors='ignore').strip()} is Writable and Executable")
                            break
                except Exception:
                    pass

        except Exception as e:
            reasons.append(f"Heuristics read error: {e}")
            entropy = 0.0

        return {
            "score": score,
            "reasons": reasons,
            "entropy": entropy
        }