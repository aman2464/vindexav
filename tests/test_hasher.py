from pathlib import Path
from engine.hasher import HashEngine

EICAR_PAYLOAD = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_hasher_eicar_detection(tmp_path: Path):
    test_file = tmp_path / "eicar.com"
    test_file.write_bytes(EICAR_PAYLOAD)

    hasher = HashEngine()
    md5, sha256 = hasher.compute_hashes(test_file)

    assert md5.lower() == "44d88612fea8a8f36de82e1278abb02f"
    assert sha256.lower() == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    result = hasher.check_local(md5, sha256)
    assert result is not None
    family, severity = result
    assert family == "EICAR-Standard-Test"
    assert severity == "malicious"


def test_hasher_benign_file(tmp_path: Path):
    test_file = tmp_path / "benign.txt"
    test_file.write_text("Regular benign non-malicious content.")

    hasher = HashEngine()
    md5, sha256 = hasher.compute_hashes(test_file)
    result = hasher.check_local(md5, sha256)
    assert result is None