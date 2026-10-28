from pathlib import Path
from typing import Dict, Any, List

from engine.hasher import StreamHasher
from engine.heuristics import HeuristicEngine
from engine.yara_scanner import YaraScanner


class DetectionPipeline:
    """Coordinates Multi-Tier Threat Detection: Hashes -> Heuristics -> YARA."""

    def __init__(self):
        self.hasher = StreamHasher()
        self.heuristics = HeuristicEngine()
        self.yara = YaraScanner()

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        p = Path(file_path)
        if not p.is_file():
            return {"verdict": "error", "score": 0, "reasons": ["File not accessible"]}

        reasons: List[str] = []
        total_score = 0

        # Stage 1: Fast-path Signature Hash Database
        h_res = self.hasher.inspect(str(p))
        sha256 = h_res.get("sha256", "")
        if h_res.get("match"):
            return {
                "verdict": "malicious",
                "score": 100,
                "sha256": sha256,
                "reasons": ["Matched known threat signature hash database"]
            }

        # Stage 2: Static Heuristic Assessment
        heur_res = self.heuristics.inspect(str(p))
        heur_score = heur_res.get("score", 0)
        total_score += heur_score
        reasons.extend(heur_res.get("reasons", []))

        # Stage 3: YARA Rules
        yara_res = self.yara.inspect(str(p))
        if yara_res.get("match"):
            total_score += yara_res.get("score", 40)
            reasons.append(f"YARA rules matched: {', '.join(yara_res.get('rules', []))}")

        total_score = min(total_score, 100)

        # Updated Threshold Logic:
        # Score < 21: Clean
        # 21 <= Score <= 45: Suspicious (Flagged as threat in red)
        # Score > 45: Malicious (Flagged as threat in red)
        if total_score > 45:
            verdict = "malicious"
        elif total_score >= 21:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "verdict": verdict,
            "score": total_score,
            "sha256": sha256,
            "entropy": heur_res.get("entropy", 0.0),
            "reasons": reasons if reasons else ["Clean scan profile"]
        }