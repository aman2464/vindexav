import os
import sys
import uuid
import logging
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from config import cfg
import database
from engine.pipeline import DetectionPipeline
from engine.quarantine import QuarantineManager

log_file = cfg.log_dir / "server.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(str(log_file), encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("vindexav-server")

pipeline: Optional[DetectionPipeline] = None
quarantine_mgr: Optional[QuarantineManager] = None
watcher_active: bool = False
watcher_observer = None


def init_engine():
    global pipeline, quarantine_mgr
    database.init_db()
    quarantine_mgr = QuarantineManager()
    pipeline = DetectionPipeline()
    logger.info("All engine components loaded.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_engine()
    yield
    global watcher_observer, watcher_active
    if watcher_observer:
        try:
            watcher_observer.stop()
            watcher_observer.join(timeout=2.0)
        except Exception as e:
            logger.error(f"Error terminating watcher: {e}")
        watcher_active = False


app = FastAPI(title="VindexAV Core Engine", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target_path: str
    scan_type: Optional[str] = "custom"


class QuarantineRequest(BaseModel):
    file_path: str
    verdict: Optional[str] = "malicious"
    reasons: Optional[str] = "Manual quarantine"
    sha256: Optional[str] = ""


@app.get("/api/status")
def get_status():
    global watcher_active, watcher_observer
    if watcher_observer is not None:
        if not watcher_observer.is_alive():
            watcher_active = False

    stats = database.get_system_stats()
    return {
        "status": "online",
        "watcher_active": bool(watcher_active),
        "database": "connected",
        "db_path": str(cfg.db_path),
        "total_scans": stats.get("total_scans", 0),
        "threats_found": stats.get("threats_found", 0),
        "quarantined_files": stats.get("quarantined_files", 0),
        "last_scan_time": stats.get("last_scan_time")
    }


@app.post("/api/watcher/start")
def start_watcher():
    global watcher_active, watcher_observer
    if watcher_active and watcher_observer and watcher_observer.is_alive():
        return {"status": "running", "message": "Real-time shield already active", "watcher_active": True}

    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class DownloadWatchHandler(FileSystemEventHandler):
            def on_created(self, event):
                if not event.is_directory and pipeline:
                    try:
                        res = pipeline.scan_file(event.src_path)
                        if res and res.get("verdict") in ("suspicious", "malicious"):
                            database.insert_detection(
                                scan_id=None,
                                file_path=event.src_path,
                                file_name=os.path.basename(event.src_path),
                                sha256=res.get("sha256", ""),
                                verdict=res.get("verdict", "malicious"),
                                score=res.get("score", 100),
                                reasons="; ".join(res.get("reasons", []))
                            )
                            if quarantine_mgr:
                                quarantine_mgr.quarantine(event.src_path, res)
                    except Exception as err:
                        logger.error(f"Watcher scan error on {event.src_path}: {err}")

        watch_path = str(Path.home() / "Downloads")
        os.makedirs(watch_path, exist_ok=True)

        if watcher_observer:
            try:
                watcher_observer.stop()
                watcher_observer.join(timeout=1.0)
            except Exception:
                pass

        event_handler = DownloadWatchHandler()
        watcher_observer = Observer()
        watcher_observer.schedule(event_handler, path=watch_path, recursive=False)
        watcher_observer.daemon = True
        watcher_observer.start()

        watcher_active = True
        logger.info(f"Real-Time Shield active on: {watch_path}")
        return {"status": "success", "message": f"Shield active on {watch_path}", "watcher_active": True}
    except Exception as e:
        watcher_active = False
        logger.error(f"Failed to start shield: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/watcher/stop")
def stop_watcher():
    global watcher_active, watcher_observer
    if watcher_observer:
        try:
            watcher_observer.stop()
            watcher_observer.join(timeout=1.5)
        except Exception:
            pass
        watcher_observer = None

    watcher_active = False
    logger.info("Real-Time Shield deactivated.")
    return {"status": "success", "message": "Shield deactivated", "watcher_active": False}


def execute_scan_task(scan_id: str, target_path: str):
    try:
        raw_path = os.path.expanduser(target_path.strip())
        p = Path(raw_path)
        if not p.is_absolute():
            p = Path.home() / p

        if not p.exists():
            database.update_scan_progress(scan_id, files_scanned=0, threats_found=0, status="failed", completed=True)
            return

        files_to_scan = []
        if p.is_file():
            files_to_scan.append(p)
        else:
            for root, dirs, files in os.walk(str(p)):
                dirs[:] = [d for d in dirs if d not in cfg.excluded_paths]
                for file in files:
                    ext = Path(file).suffix.lower()
                    if ext not in cfg.excluded_extensions:
                        files_to_scan.append(Path(root) / file)

        total_files = len(files_to_scan)
        threats_count = 0

        if total_files == 0:
            database.update_scan_progress(scan_id, files_scanned=0, threats_found=0, status="completed", completed=True)
            return

        for idx, file_path in enumerate(files_to_scan, start=1):
            try:
                if file_path.stat().st_size <= (cfg.max_file_size_mb * 1024 * 1024):
                    res = pipeline.scan_file(str(file_path)) if pipeline else None
                    if res:
                        is_threat = res.get("verdict") in ("suspicious", "malicious")
                        if is_threat:
                            threats_count += 1

                        # Record all scanned items in findings
                        database.insert_detection(
                            scan_id=scan_id,
                            file_path=str(file_path),
                            file_name=file_path.name,
                            sha256=res.get("sha256", ""),
                            verdict=res.get("verdict", "clean"),
                            score=res.get("score", 0),
                            reasons="; ".join(res.get("reasons", [])),
                            quarantined=False
                        )
            except Exception as fe:
                logger.error(f"Error scanning {file_path}: {fe}")

            database.update_scan_progress(scan_id, files_scanned=idx, threats_found=threats_count, status="running")

        database.update_scan_progress(scan_id, files_scanned=total_files, threats_found=threats_count, status="completed", completed=True)
        logger.info(f"Scan {scan_id} finished: {total_files} files, {threats_count} threats.")
    except Exception as e:
        logger.error(f"Scan task error: {e}")
        database.update_scan_progress(scan_id, files_scanned=0, threats_found=0, status="failed", completed=True)


@app.post("/api/scan")
def trigger_scan(payload: ScanRequest, background_tasks: BackgroundTasks):
    target = payload.target_path.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target path is required.")

    scan_id = str(uuid.uuid4())[:8]
    database.insert_scan(scan_id, target, payload.scan_type, status="running")
    background_tasks.add_task(execute_scan_task, scan_id, target)

    return {"status": "started", "scan_id": scan_id, "target_path": target}


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    detections = database.get_detections_for_scan(scan_id)
    scan["detections"] = detections
    return scan


@app.get("/api/history")
def get_history():
    return database.get_all_scans()


@app.get("/api/quarantine")
def list_quarantine():
    return database.get_quarantine_items()


@app.post("/api/quarantine/file")
def quarantine_target_file(payload: QuarantineRequest):
    if not quarantine_mgr:
        raise HTTPException(status_code=500, detail="Quarantine subsystem not ready.")
    
    detection_payload = {
        "sha256": payload.sha256,
        "verdict": payload.verdict,
        "reasons": [payload.reasons]
    }
    success, msg = quarantine_mgr.quarantine(payload.file_path, detection_payload)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "quarantined", "message": msg}


@app.post("/api/quarantine/{item_id}/restore")
def restore_file(item_id: int):
    if not quarantine_mgr:
        raise HTTPException(status_code=500, detail="Quarantine subsystem not ready.")
    success, msg = quarantine_mgr.restore(item_id)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "restored", "message": msg}


@app.delete("/api/quarantine/{item_id}")
def delete_file(item_id: int):
    if not quarantine_mgr:
        raise HTTPException(status_code=500, detail="Quarantine subsystem not ready.")
    success, msg = quarantine_mgr.delete(item_id)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "deleted", "message": msg}


def run():
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__" or getattr(sys, "frozen", False):
    run()