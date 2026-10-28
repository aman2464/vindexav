import os
from pathlib import Path
from typing import Dict, Any, List
from config import cfg

try:
    import yara
except ImportError:
    yara = None


class YaraScanner:
    """Loads and compiles rule files to scan target files for signature matches."""

    def __init__(self):
        self.rules = None
        self.compile_rules()

    def compile_rules(self):
        if not yara:
            return

        rules_dir = getattr(cfg, "rules_dir", None)
        if not rules_dir or not Path(rules_dir).exists():
            return

        filepaths = {}
        for r_file in Path(rules_dir).glob("*.yar*"):
            filepaths[r_file.stem] = str(r_file)

        if filepaths:
            try:
                self.rules = yara.compile(filepaths=filepaths)
            except Exception:
                self.rules = None

    def inspect(self, file_path: str) -> Dict[str, Any]:
        p = Path(file_path)
        if not yara or not self.rules or not p.is_file():
            return {"match": False, "rules": [], "score": 0}

        try:
            matches = self.rules.match(str(p), timeout=10)
            rule_names = [m.rule for m in matches]
            match_found = len(rule_names) > 0
            return {
                "match": match_found,
                "rules": rule_names,
                "score": 40 if match_found else 0
            }
        except Exception:
            return {"match": False, "rules": [], "score": 0}