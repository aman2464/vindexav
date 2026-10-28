import secrets
from pathlib import Path
from engine.heuristics import HeuristicsEngine


def test_entropy_calculation():
    heur = HeuristicsEngine()
    # Uniform / Low entropy
    uniform_data = b"A" * 1024
    assert heur.calculate_entropy(uniform_data) == 0.0

    # High entropy (random byte array)
    random_data = secrets.token_bytes(8192)
    score, reasons = heur.analyze_entropy(random_data)
    assert score == 30
    assert any("High Shannon entropy" in r for r in reasons)


def test_double_extension_detection():
    heur = HeuristicsEngine()
    score, reasons = heur.analyze_extensions("invoice.pdf.exe")
    assert score == 20
    assert any("Deceptive double extension" in r for r in reasons)

    # Legitimate multi-dot file
    score, reasons = heur.analyze_extensions("archive.tar.gz")
    assert score == 0


def test_magic_mismatch_detection():
    heur = HeuristicsEngine()
    # Executable pretending to be an image
    fake_png = b"MZ\x90\x00\x03\x00\x00\x00"
    score, reasons = heur.analyze_magic_mismatch(".png", fake_png)
    assert score >= 25