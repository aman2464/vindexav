from pathlib import Path
from engine.quarantine import QuarantineVault


def test_quarantine_encrypt_and_restore_cycle(tmp_path: Path):
    vault = QuarantineVault()
    sample_file = tmp_path / "sensitive_payload.bin"
    original_data = b"SUSPICIOUS_PAYLOAD_BYTE_STREAM_FOR_ISOLATION"
    sample_file.write_bytes(original_data)

    # 1. Quarantine
    record_id = vault.quarantine_file(
        file_path=sample_file,
        sha256_hash="testsha256",
        verdict="malicious",
        reasons="Test reasons"
    )
    assert record_id is not None
    assert not sample_file.exists()  # Original must be shredded and unlinked

    # 2. Restore
    success, restored_path = vault.restore_file(record_id)
    assert success is True
    restored_p = Path(restored_path)
    assert restored_p.exists()
    assert restored_p.read_bytes() == original_data