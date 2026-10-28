from pathlib import Path
from engine.yara_scanner import YaraScanner

EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_yara_eicar_rule(tmp_path: Path):
    scanner = YaraScanner()
    test_file = tmp_path / "yara_test_eicar.bin"
    test_file.write_bytes(EICAR_BYTES)

    matched, reasons, severity = scanner.scan_file(test_file)
    assert matched is True
    assert severity == "malicious"
    assert any("EICAR" in r for r in reasons)


def test_yara_clean_file(tmp_path: Path):
    scanner = YaraScanner()
    test_file = tmp_path / "clean_note.txt"
    test_file.write_text("Hello world, this is a clean file without triggers.")

    matched, reasons, severity = scanner.scan_file(test_file)
    assert matched is False
    assert severity == "clean"