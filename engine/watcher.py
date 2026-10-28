import os
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification

from config import cfg
from engine.pipeline import DetectionPipeline
from engine.quarantine import QuarantineVault
from database import insert_detection
from logger import logger


def send_system_alert(title: str, message: str):
    """Triggers cross-platform OS desktop popups."""
    try:
        icon_path = str(cfg.base_dir / "assets" / "icon.png")
        notification.notify(
            title=title,
            message=message,
            app_name="VindexAV",
            app_icon=icon_path if os.path.exists(icon_path) else None,
            timeout=8
        )
    except Exception as e:
        logger.warning(f"Could not trigger system notification: {e}")


class WatcherHandler(FileSystemEventHandler):
    def __init__(self, pipeline: DetectionPipeline, vault: QuarantineVault):
        super().__init__()
        self.pipeline = pipeline
        self.vault = vault
        self.vault_dir = cfg.vault_dir.resolve()

    def _wait_for_file_settled(self, path: Path, timeout: float = 3.0) -> bool:
        start_time = time.time()
        last_size = -1
        while time.time() - start_time < timeout:
            if not path.exists():
                return False
            try:
                current_size = path.stat().st_size
                if current_size == last_size and current_size > 0:
                    return True
                last_size = current_size
            except OSError:
                pass
            time.sleep(0.3)
        return path.exists()

    def on_created(self, event):
        if not event.is_directory:
            self._process(Path(event.src_path))

    def on_modified(self, event):
        if not event.is_directory:
            self._process(Path(event.src_path))

    def _process(self, file_path: Path):
        file_path = file_path.resolve()

        # Prevent circular loop inside quarantine vault
        try:
            if self.vault_dir in file_path.parents or file_path == self.vault_dir:
                return
        except Exception:
            return

        if not self._wait_for_file_settled(file_path):
            return

        if not file_path.is_file():
            return

        logger.info(f"Watcher inspecting: {file_path.name}")
        result = self.pipeline.scan_file(file_path)

        if result["verdict"] in ("malicious", "suspicious"):
            logger.warning(f"Threat Intercepted: {file_path.name} [{result['verdict'].upper()}]")
            quarantined = False

            if result["verdict"] == "malicious":
                q_id = self.vault.quarantine_file(
                    file_path=file_path,
                    sha256_hash=result["sha256"],
                    verdict=result["verdict"],
                    reasons="; ".join(result["reasons"])
                )
                quarantined = (q_id is not None)

            # Trigger Native Desktop Notification
            alert_header = "Malware Quarantined!" if quarantined else "Threat Detected!"
            alert_body = f"File: {file_path.name}\nThreat Level: {result['verdict'].upper()}\nScore: {result['risk_score']}/100"
            send_system_alert(alert_header, alert_body)

            insert_detection(
                scan_id=None,
                file_path=str(file_path),
                file_name=file_path.name,
                sha256=result["sha256"],
                verdict=result["verdict"],
                score=result["risk_score"],
                reasons="; ".join(result["reasons"]),
                quarantined=quarantined
            )


class RealtimeWatcher:
    def __init__(self, pipeline: DetectionPipeline, vault: QuarantineVault):
        self.pipeline = pipeline
        self.vault = vault
        self.observer = None
        self.is_running = False

    def start(self) -> bool:
        if self.is_running:
            return True

        self.observer = Observer()
        handler = WatcherHandler(self.pipeline, self.vault)

        watch_targets = [
            Path.home() / "Downloads",
            cfg.base_dir / "test_folder"
        ]

        watch_count = 0
        for p in watch_targets:
            p.mkdir(parents=True, exist_ok=True)
            self.observer.schedule(handler, str(p), recursive=True)
            watch_count += 1
            logger.info(f"Real-time interceptor active on: {p}")

        if watch_count > 0:
            self.observer.start()
            self.is_running = True
            return True
        return False

    def stop(self) -> bool:
        if not self.is_running or not self.observer:
            return False

        self.observer.stop()
        self.observer.join(timeout=3)
        self.is_running = False
        return True