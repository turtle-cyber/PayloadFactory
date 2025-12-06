from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import sys
import os
import logging

# Add project root to sys.path to import ml_engine
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from ml_engine.model import VulnerabilityScanner
from ml_engine.patch_generator import PatchGenerator

router = APIRouter()
logger = logging.getLogger(__name__)

# Lazy loading of models to avoid startup delay during development
scanner = None
patch_generator = None

def get_scanner():
    global scanner
    if scanner is None:
        logger.info("Initializing VulnerabilityScanner...")
        scanner = VulnerabilityScanner()
    return scanner

def get_patch_generator():
    global patch_generator
    if patch_generator is None:
        logger.info("Initializing PatchGenerator...")
        patch_generator = PatchGenerator()
    return patch_generator

class ScanRequest(BaseModel):
    code: str

class PatchRequest(BaseModel):
    code: str

@router.post("/scan")
async def scan_code(request: ScanRequest):
    try:
        scanner_instance = get_scanner()
        result = scanner_instance.scan(request.code)
        return result
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/patch")
async def generate_patch(request: PatchRequest):
    try:
        generator_instance = get_patch_generator()
        patch = generator_instance.generate_patch(request.code)
        return {"patch": patch}
    except Exception as e:
        logger.error(f"Patch generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# --- CTF Pipeline Endpoints ---

from ml_engine.recon_module import ReconScanner
from ml_engine.exploit_generator import ExploitGenerator
from ml_engine.fuzzing_module import Fuzzer
from ml_engine.rl_agent import RLAgent

# Lazy loaders for new modules
recon_scanner = None
exploit_gen = None
fuzzer_instance = None
rl_agent = None

def get_recon_scanner():
    global recon_scanner
    if recon_scanner is None:
        recon_scanner = ReconScanner()
    return recon_scanner

def get_exploit_gen():
    global exploit_gen
    if exploit_gen is None:
        exploit_gen = ExploitGenerator()
    return exploit_gen

def get_fuzzer():
    global fuzzer_instance
    if fuzzer_instance is None:
        fuzzer_instance = Fuzzer()
    return fuzzer_instance

def get_rl_agent():
    global rl_agent
    if rl_agent is None:
        rl_agent = RLAgent()
    return rl_agent

class ReconRequest(BaseModel):
    url: str

class ExploitRequest(BaseModel):
    vulnerability_details: str

class FuzzRequest(BaseModel):
    target_ip: str
    base_payload: str

class RLRequest(BaseModel):
    initial_payload: str

@router.post("/recon")
async def run_recon(request: ReconRequest):
    try:
        scanner = get_recon_scanner()
        return scanner.scan_target(request.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/generate_exploit")
async def generate_exploit_endpoint(request: ExploitRequest):
    try:
        gen = get_exploit_gen()
        exploit = gen.generate_exploit(request.vulnerability_details)
        return {"exploit_code": exploit}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/fuzz")
async def run_fuzzing(request: FuzzRequest):
    try:
        fuzzer = get_fuzzer()
        fuzzer.target_ip = request.target_ip # Update target
        results = fuzzer.run_fuzzing_session(request.base_payload)
        return {"crashes": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/optimize_exploit")
async def optimize_exploit_endpoint(request: RLRequest):
    try:
        agent = get_rl_agent()
        optimized_payload = agent.optimize_exploit(request.initial_payload)
        return {"optimized_payload": optimized_payload}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Remote Agent Endpoint ---

from ml_engine.db_manager import DatabaseManager

# Lazy loader for DB
db_manager = None

def get_db():
    global db_manager
    if db_manager is None:
        db_manager = DatabaseManager()
    return db_manager

class AgentLogRequest(BaseModel):
    metadata: dict
    type: str = "log"  # log or metric
    log_file: str = None
    content: str
    timestamp: float
    priority: str = None  # high, low, verbose, none
    category: str = None  # CRASH, RCE, DOS, etc.
    matched_keyword: str = None
    metrics: dict = None  # For metric type

# Configure logger for agent logs (to be visible in GUI)
from ml_engine.logger_config import setup_logger
agent_logger = setup_logger("agent_logger", "scan_log.json")

@router.post("/agent/logs")
async def receive_agent_logs(request: AgentLogRequest):
    try:
        # 1. Save to MongoDB (Persistent Storage)
        db = get_db()
        log_data = request.dict()
        db.save_agent_log(log_data)
        
        # 2. Log to file (For GUI Real-time Display)
        # Format: "Received agent log from <hostname>: <message>"
        hostname = log_data.get('metadata', {}).get('hostname', 'Unknown')
        message = log_data.get('content', '')
        agent_logger.info(f"Received agent log from {hostname}: {message}")
        
        return {"status": "received"}
    except Exception as e:
        logger.error(f"Failed to process agent log: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# --- Scan Orchestrator Endpoints ---

from server.app.scan_orchestrator import get_orchestrator

class StartScanRequest(BaseModel):
    target_dir: str
    project_name: str = None
    quick_scan: bool = False
    demo_mode: bool = False
    remote_host: str = None
    remote_port: int = None
    model: str = "hermes"

@router.post("/start-scan")
async def start_scan(request: StartScanRequest):
    """Start a new vulnerability scan."""
    try:
        if not os.path.isdir(request.target_dir):
            raise HTTPException(status_code=400, detail="Target directory does not exist")
        
        orchestrator = get_orchestrator()
        result = orchestrator.start_scan(
            target_dir=request.target_dir,
            project_name=request.project_name,
            quick_scan=request.quick_scan,
            demo_mode=request.demo_mode,
            remote_host=request.remote_host,
            remote_port=request.remote_port,
            model=request.model
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan-status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get the current status of a scan."""
    try:
        orchestrator = get_orchestrator()
        result = orchestrator.get_scan_status(scan_id)
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/stop-scan/{scan_id}")
async def stop_scan(scan_id: str):
    """Cancel a running scan."""
    try:
        orchestrator = get_orchestrator()
        result = orchestrator.stop_scan(scan_id)
        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to stop scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

