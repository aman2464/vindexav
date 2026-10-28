import pytest
from pathlib import Path
import shutil
import tempfile
import os

from config import cfg
import database

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    temp_dir = tempfile.mkdtemp(prefix="vindex_test_")
    test_db = Path(temp_dir) / "test_vindex.db"
    test_vault = Path(temp_dir) / "test_vault"
    test_key = Path(temp_dir) / "test_quarantine.key"

    # Save original values
    orig_db = cfg._data.get("db_file")
    orig_vault = cfg._data.get("vault_dir")
    orig_key = cfg._data.get("key_file")

    # Patch paths in internal configuration store
    cfg._data["db_file"] = str(test_db)
    cfg._data["vault_dir"] = str(test_vault)
    cfg._data["key_file"] = str(test_key)

    database.init_db()

    yield

    # Restore original configuration
    if orig_db is not None:
        cfg._data["db_file"] = orig_db
    if orig_vault is not None:
        cfg._data["vault_dir"] = orig_vault
    if orig_key is not None:
        cfg._data["key_file"] = orig_key

    shutil.rmtree(temp_dir, ignore_errors=True)