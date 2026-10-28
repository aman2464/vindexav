import logging
import sys
from pathlib import Path
from config import cfg

# Logs will be safely written inside ~/.vindexav/logs/
log_file = cfg.log_dir / "engine.log"

logger = logging.getLogger("VindexAV")
logger.setLevel(logging.INFO)

if not logger.handlers:
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler
    c_handler = logging.StreamHandler(sys.stdout)
    c_handler.setFormatter(formatter)
    logger.addHandler(c_handler)

    # File Handler in ~/.vindexav/logs/
    try:
        f_handler = logging.FileHandler(log_file, encoding="utf-8")
        f_handler.setFormatter(formatter)
        logger.addHandler(f_handler)
    except Exception as e:
        print(f"Warning: Could not open log file {log_file}: {e}")