import os
import sys
import json
from pathlib import Path

# Static read-only bundle directory (frozen binary vs dev tree)
if getattr(sys, 'frozen', False):
    BUNDLE_DIR = Path(sys._MEIPASS)
else:
    BUNDLE_DIR = Path(__file__).resolve().parent

# Writable user runtime directory inside home directory
USER_DATA_DIR = Path.home() / ".vindexav"
USER_DATA_DIR.mkdir(parents=True, exist_ok=True)


class Config:
    def __init__(self):
        self.base_dir = BUNDLE_DIR
        self.data_dir = USER_DATA_DIR

        # Dynamic writable paths
        self.log_dir = self.data_dir / "logs"
        self.vault_dir = self.data_dir / "quarantine_vault"
        self.quarantine_dir = self.vault_dir
        self.db_path = self.data_dir / "vindexav.db"

        # Static asset directories
        self.rules_dir = self.base_dir / "rules"
        self.yara_rules_dir = self.rules_dir
        self.signatures_dir = self.base_dir / "signatures"
        self.assets_dir = self.base_dir / "assets"

        # Static rule files / paths
        self.rules_file = self.rules_dir / "rules.yar"
        self.yara_file = self.rules_file
        self.rules_path = self.rules_dir

        # Signatures file resolution
        sig_candidates = [
            self.signatures_dir / "signatures.json",
            self.signatures_dir / "known_hashes.json",
            self.signatures_dir / "malware_hashes.json"
        ]
        self.signatures_file = sig_candidates[0]
        for candidate in sig_candidates:
            if candidate.exists():
                self.signatures_file = candidate
                break

        # Scoring weights for heuristics
        self.scores = {
            "high_entropy": 30,
            "double_extension": 20,
            "pe_anomaly": 35,
            "yara_match": 40,
            "known_hash": 100,
            "magic_mismatch": 25,
            "suspicious_string": 15
        }

        # Scanning thresholds & cutoffs
        self.entropy_cutoff = 7.2
        self.entropy_threshold = 7.2
        self.max_file_size_mb = 100
        self.excluded_paths = [".git", ".venv", "node_modules", "__pycache__"]
        self.excluded_extensions = [".tmp", ".log"]

        self._load_from_file()

        # Ensure dynamic directories exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.vault_dir.mkdir(parents=True, exist_ok=True)

    def _load_from_file(self):
        config_file = self.base_dir / "config.json"
        if not config_file.exists():
            config_file = Path.cwd() / "config.json"

        if config_file.exists():
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    val = data.get("entropy_cutoff", data.get("entropy_threshold", 7.2))
                    self.entropy_cutoff = val
                    self.entropy_threshold = val
                    self.max_file_size_mb = data.get("max_file_size_mb", self.max_file_size_mb)
                    self.excluded_paths = data.get("excluded_paths", self.excluded_paths)
                    self.excluded_extensions = data.get("excluded_extensions", self.excluded_extensions)
                    if "scores" in data and isinstance(data["scores"], dict):
                        self.scores.update(data["scores"])
            except Exception:
                pass

    def __getattr__(self, name):
        """Fallback to valid Path objects instead of None so .exists() never crashes."""
        if any(term in name for term in ["dir", "path", "file", "rule"]):
            return self.rules_dir
        defaults = {
            "entropy_cutoff": 7.2,
            "entropy_threshold": 7.2,
            "scores": self.scores,
            "max_file_size_mb": 100,
            "excluded_paths": self.excluded_paths,
            "excluded_extensions": self.excluded_extensions
        }
        return defaults.get(name, None)


cfg = Config()