from pathlib import Path
from engine.pipeline import DetectionPipeline

EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_pipeline_on_eicar(tmp_path: Path):
    pipeline = DetectionPipeline()
    eicar_file = tmp_path / "eicar.com"
    eicar_file.write_bytes(EICAR_BYTES)

    res = pipeline.scan_file(eicar_file)
    assert res["verdict"] == "malicious"
    assert res["risk_score"] >= 80
    assert any("EICAR" in r for r in res["reasons"])


def test_pipeline_on_clean_file(tmp_path: Path):
    pipeline = DetectionPipeline()
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("Plain text sample.")

    res = pipeline.scan_file(clean_file)
    assert res["verdict"] == "clean"
    assert res["risk_score"] < 50