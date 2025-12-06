"""
Scan Orchestrator - Manages the 3-stage scanning pipeline.

Provides background execution of scan stages and progress tracking.
"""
import os
import sys
import threading
import subprocess
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum

# Add project root to sys.path (2 levels up from server/app/)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../..")))

from ml_engine.db_manager import DatabaseManager

logger = logging.getLogger(__name__)


class ScanStatus(str, Enum):
    PENDING = "pending"
    STAGE_1 = "stage-1"
    STAGE_2 = "stage-2"
    STAGE_3 = "stage-3"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanOrchestrator:
    """Manages the lifecycle of vulnerability scans."""

    def __init__(self):
        self.db = DatabaseManager()
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        # Get absolute path to project root (2 levels up from server/app/)
        # Using os.path.abspath(__file__) ensures correct path regardless of CWD
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
        logger.info(f"ScanOrchestrator initialized with project_root: {self.project_root}")
    
    def start_scan(
        self,
        target_dir: str,
        project_name: Optional[str] = None,
        quick_scan: bool = False,
        demo_mode: bool = False,
        remote_host: Optional[str] = None,
        remote_port: Optional[int] = None,
        model: Optional[str] = "hermes"
    ) -> Dict[str, Any]:
        """
        Start a new scan in a background thread.
        
        Returns:
            Dict with scan_id and initial status
        """
        # Create scan record in DB
        scan_id = self.db.create_scan(
            project_name=project_name or os.path.basename(target_dir),
            root_path=target_dir,
            file_size=self._get_dir_size(target_dir)
        )
        
        # Initialize progress
        self.db.update_scan_progress(scan_id, {
            "status": ScanStatus.PENDING,
            "progress": {
                "current_stage": 0,
                "files_scanned": 0,
                "total_files": 0,
                "vulnerabilities_found": 0,
                "exploits_generated": 0,
                "current_file": None
            }
        })
        
        # Store scan config
        scan_config = {
            "target_dir": target_dir,
            "quick_scan": quick_scan,
            "demo_mode": demo_mode,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "model": model or "hermes",
            "thread": None,
            "cancelled": False
        }
        self.active_scans[scan_id] = scan_config
        
        # Start background thread
        thread = threading.Thread(
            target=self._run_scan_pipeline,
            args=(scan_id, scan_config),
            daemon=True
        )
        scan_config["thread"] = thread
        thread.start()
        
        logger.info(f"Started scan {scan_id} for {target_dir}")
        
        return {
            "scan_id": scan_id,
            "status": ScanStatus.PENDING,
            "message": "Scan started"
        }
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get current status and progress of a scan."""
        scan = self.db.get_scan(scan_id)
        if not scan:
            return {"error": "Scan not found", "scan_id": scan_id}
        
        return {
            "scan_id": scan_id,
            "status": scan.get("status", "unknown"),
            "progress": scan.get("progress", {}),
            "project_name": scan.get("project_name"),
            "started_at": scan.get("timestamps", {}).get("submitted_at"),
            "completed_at": scan.get("timestamps", {}).get("completed_at")
        }
    
    def stop_scan(self, scan_id: str) -> Dict[str, Any]:
        """Cancel a running scan."""
        if scan_id not in self.active_scans:
            return {"error": "Scan not active or already completed", "scan_id": scan_id}
        
        self.active_scans[scan_id]["cancelled"] = True
        self.db.update_scan_progress(scan_id, {"status": ScanStatus.CANCELLED})
        
        logger.info(f"Cancelled scan {scan_id}")
        
        return {
            "scan_id": scan_id,
            "status": ScanStatus.CANCELLED,
            "message": "Scan cancelled"
        }
    
    def _run_scan_pipeline(self, scan_id: str, config: Dict[str, Any]):
        """Execute the 3-stage scan pipeline."""
        target_dir = config["target_dir"]
        intermediate_file = os.path.join(self.project_root, f"intermediate_{scan_id}.json")
        output_dir = os.path.join(self.project_root, "exploits")
        
        try:
            # Stage 1: Specialized model scanning
            if config["cancelled"]:
                return
            
            self.db.update_scan_progress(scan_id, {
                "status": ScanStatus.STAGE_1,
                "progress.current_stage": 1
            })
            
            stage1_cmd = [
                sys.executable,
                os.path.join(self.project_root, "scan_stage_1.py"),
                target_dir,
                intermediate_file,
                "--scan-id", scan_id
            ]
            if config["quick_scan"]:
                stage1_cmd.append("--quick-scan")

            logger.info(f"Executing Stage 1 command: {' '.join(stage1_cmd)}")
            result = subprocess.run(stage1_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Stage 1 stderr: {result.stderr}")
                logger.error(f"Stage 1 stdout: {result.stdout}")
                raise Exception(f"Stage 1 failed: {result.stderr}")
            
            # Stage 2: LLM classification and exploit generation
            if config["cancelled"]:
                return
            
            self.db.update_scan_progress(scan_id, {
                "status": ScanStatus.STAGE_2,
                "progress.current_stage": 2
            })
            
            stage2_cmd = [
                sys.executable,
                os.path.join(self.project_root, "scan_stage_2.py"),
                target_dir,
                output_dir,
                intermediate_file,
                "--scan-id", scan_id
            ]
            if config["demo_mode"]:
                stage2_cmd.append("--demo-mode")
            if config.get("model"):
                stage2_cmd.extend(["--model", config["model"]])
            if config["remote_host"]:
                stage2_cmd.extend(["--remote-host", config["remote_host"]])
            if config["remote_port"]:
                stage2_cmd.extend(["--remote-port", str(config["remote_port"])])
            
            result = subprocess.run(stage2_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Stage 2 failed: {result.stderr}")
            
            # Stage 3: Fuzzing and RL optimization
            if config["cancelled"]:
                return
            
            self.db.update_scan_progress(scan_id, {
                "status": ScanStatus.STAGE_3,
                "progress.current_stage": 3
            })
            
            stage3_cmd = [
                sys.executable,
                os.path.join(self.project_root, "scan_stage_3.py"),
                output_dir,
                "--scan-id", scan_id
            ]
            if config["remote_host"]:
                stage3_cmd.extend(["--remote-host", config["remote_host"]])
            if config["remote_port"]:
                stage3_cmd.extend(["--remote-port", str(config["remote_port"])])
            
            result = subprocess.run(stage3_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Stage 3 failed: {result.stderr}")
            
            # Mark as completed
            self.db.update_scan_progress(scan_id, {
                "status": ScanStatus.COMPLETED,
                "timestamps.completed_at": datetime.utcnow().isoformat()
            })
            
            logger.info(f"Scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            self.db.update_scan_progress(scan_id, {
                "status": ScanStatus.FAILED,
                "error": str(e)
            })
        
        finally:
            # Cleanup
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
            # Remove intermediate file
            if os.path.exists(intermediate_file):
                try:
                    os.remove(intermediate_file)
                except:
                    pass
    
    def _get_dir_size(self, path: str) -> int:
        """Calculate total size of directory in bytes."""
        total_size = 0
        try:
            for dirpath, dirnames, filenames in os.walk(path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if os.path.isfile(fp):
                        total_size += os.path.getsize(fp)
        except:
            pass
        return total_size


# Global instance
_orchestrator = None

def get_orchestrator() -> ScanOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = ScanOrchestrator()
    return _orchestrator
