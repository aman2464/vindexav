import os
import shutil
import uuid
from pathlib import Path
from typing import Tuple, Dict, Any, Optional
from cryptography.fernet import Fernet

from config import cfg
import database


class QuarantineManager:
    """Manages isolated, Fernet-encrypted file containment."""

    def __init__(self):
        self.vault_dir = Path(cfg.vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.key_file = Path(cfg.data_dir) / ".vault.key"
        self.cipher = Fernet(self._get_or_create_key())

    def _get_or_create_key(self) -> bytes:
        if self.key_file.exists():
            return self.key_file.read_bytes()
        key = Fernet.generate_key()
        self.key_file.write_bytes(key)
        try:
            os.chmod(self.key_file, 0o600)
        except Exception:
            pass
        return key

    def quarantine(self, file_path: str, detection_result: Dict[str, Any]) -> Tuple[bool, str]:
        path = Path(file_path)
        if not path.exists():
            return False, f"File {file_path} not found"

        try:
            file_data = path.read_bytes()
            encrypted_data = self.cipher.encrypt(file_data)
            vault_name = f"{uuid.uuid4().hex}.vxq"
            vault_file = self.vault_dir / vault_name
            vault_file.write_bytes(encrypted_data)

            # Restrict vault file execution and permissions
            try:
                os.chmod(vault_file, 0o600)
            except Exception:
                pass

            # Wipe and remove original file
            try:
                path.write_bytes(b"\x00" * len(file_data))
            except Exception:
                pass
            path.unlink(missing_ok=True)

            sha256 = detection_result.get("sha256", "")
            verdict = detection_result.get("verdict", "malicious")
            reasons = "; ".join(detection_result.get("reasons", []))

            database.insert_quarantine_record(
                original_path=str(path.resolve()),
                vault_filename=vault_name,
                sha256=sha256,
                verdict=verdict,
                reasons=reasons
            )
            return True, f"Quarantined to {vault_name}"
        except Exception as e:
            return False, f"Failed to quarantine: {e}"

    def restore(self, item_id: int) -> Tuple[bool, str]:
        item = database.get_quarantine_item(item_id)
        if not item:
            return False, "Item record not found"

        vault_file = self.vault_dir / item["vault_filename"]
        target_path = Path(item["original_path"])

        if not vault_file.exists():
            return False, "Vault file missing from storage"

        try:
            encrypted_data = vault_file.read_bytes()
            decrypted_data = self.cipher.decrypt(encrypted_data)

            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(decrypted_data)
            vault_file.unlink(missing_ok=True)
            database.delete_quarantine_record(item_id)

            return True, f"Restored to {target_path}"
        except Exception as e:
            return False, f"Restoration failed: {e}"

    def delete(self, item_id: int) -> Tuple[bool, str]:
        item = database.get_quarantine_item(item_id)
        if not item:
            return False, "Item record not found"

        vault_file = self.vault_dir / item["vault_filename"]
        if vault_file.exists():
            vault_file.unlink(missing_ok=True)

        database.delete_quarantine_record(item_id)
        return True, "Permanently deleted from quarantine"


# Standalone function aliases for external callers
_global_mgr: Optional[QuarantineManager] = None

def get_manager() -> QuarantineManager:
    global _global_mgr
    if _global_mgr is None:
        _global_mgr = QuarantineManager()
    return _global_mgr

def quarantine_file(file_path: str, result: Dict[str, Any]):
    return get_manager().quarantine(file_path, result)

def restore_quarantined_file(item_id: int):
    return get_manager().restore(item_id)

def delete_quarantined_file(item_id: int):
    return get_manager().delete(item_id)