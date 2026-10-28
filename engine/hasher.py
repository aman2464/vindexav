import hashlib
import json
from pathlib import Path
from typing import Dict, Any, Set
from config import cfg


class StreamHasher:
    """Calculates cryptographic digests and cross-references against known threat databases."""

    def __init__(self):
        self.known_signatures: Set[str] = set()
        self._load_signatures()

    def _load_signatures(self):
        # EICAR standard anti-virus test file SHA-256
        self.known_signatures.add("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        self.known_signatures.add("44d88612fea8a8f36de82e1278abb02f") # EICAR MD5

        sig_file = getattr(cfg, "signatures_file", None)
        if sig_file and Path(sig_file).exists():
            try:
                with open(sig_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                self.known_signatures.add(item.lower())
                            elif isinstance(item, dict) and "hash" in item:
                                self.known_signatures.add(item["hash"].lower())
                    elif isinstance(data, dict):
                        for h in data.get("hashes", []):
                            self.known_signatures.add(h.lower())
            except Exception:
                pass

    def inspect(self, file_path: str) -> Dict[str, Any]:
        p = Path(file_path)
        if not p.is_file():
            return {"error": "File does not exist", "score": 0, "match": False}

        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        try:
            with open(p, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    md5.update(chunk)
                    sha256.update(chunk)

            h_md5 = md5.hexdigest().lower()
            h_sha256 = sha256.hexdigest().lower()

            match = (h_sha256 in self.known_signatures) or (h_md5 in self.known_signatures)
            return {
                "md5": h_md5,
                "sha256": h_sha256,
                "file_size": p.stat().st_size,
                "match": match,
                "score": 100 if match else 0
            }
        except Exception as e:
            return {"error": str(e), "score": 0, "match": False}