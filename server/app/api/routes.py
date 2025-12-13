from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import sys
import os
import logging

# Add project root to sys.path to import ml_engine
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from ml_engine.model import VulnerabilityScanner
from ml_engine.patch_generator import PatchGenerator
from ml_engine.network_scanner import NetworkScanner
from ml_engine.service_analyzer import ServiceAnalyzer
from ml_engine.blackbox_exploitation import BlackboxExploiter

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

# Network Recon modules
network_scanner = None
service_analyzer = None
blackbox_exploiter = None

def get_network_scanner():
    global network_scanner
    if network_scanner is None:
        logger.info("Initializing NetworkScanner...")
        network_scanner = NetworkScanner()
    return network_scanner

def get_service_analyzer():
    global service_analyzer
    if service_analyzer is None:
        logger.info("Initializing ServiceAnalyzer...")
        service_analyzer = ServiceAnalyzer(model_id="hermes")
    return service_analyzer

def get_blackbox_exploiter():
    global blackbox_exploiter
    if blackbox_exploiter is None:
        logger.info("Initializing BlackboxExploiter...")
        blackbox_exploiter = BlackboxExploiter()
    return blackbox_exploiter

class ReconRequest(BaseModel):
    url: str

class ExploitRequest(BaseModel):
    vulnerability_details: str

class FuzzRequest(BaseModel):
    target_ip: str
    base_payload: str

class RLRequest(BaseModel):
    initial_payload: str

class NetworkScanRequest(BaseModel):
    target_ip: str
    ports: str = ""  # Empty = nmap auto-detect (quick scan)
    application_name: str = "Unknown Target"

class ServiceAnalysisRequest(BaseModel):
    services: List[Dict[str, Any]]
    model: str = "hermes"

class BlackboxAnalysisRequest(BaseModel):
    target_ip: str
    ports: str = ""  # Empty = nmap auto-detect (quick scan)
    services: List[Dict[str, Any]] = []

class WhiteboxWorkflowRequest(BaseModel):
    source_path: str
    target_ip: str
    target_port: str = "8080"
    application_name: str = "Whitebox Target"
    # Attack mode settings (enabled by default for whitebox)
    attack_mode: bool = True
    auto_execute: bool = True
    demo_mode: bool = False

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


class StartAttackRequest(BaseModel):
    selected_exploits: List[str] = []  # List of exploit filenames
    run_all: bool = False  # If True, run all exploits


@router.post("/scan/{scan_id}/start-attack")
async def start_attack(scan_id: str, request: StartAttackRequest):
    """
    Resume Stage 3 with selected exploits.
    
    Call this after Stage 2 completes (status='awaiting-selection') 
    to start the attack phase with only the exploits the user selected.
    """
    try:
        orchestrator = get_orchestrator()
        result = orchestrator.resume_stage_3(
            scan_id=scan_id,
            selected_exploits=request.selected_exploits,
            run_all=request.run_all
        )
        
        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start attack: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan-logs/{scan_id}")
async def get_scan_logs(scan_id: str, offset: int = 0, limit: int = 100):
    """Get logs for a specific scan with pagination."""
    try:
        from ml_engine.db_manager import DatabaseManager
        db = DatabaseManager()
        logs, total = db.get_scan_logs(scan_id, offset=offset, limit=limit)
        return {
            "success": True,
            "data": {
                "logs": logs,
                "total": total,
                "offset": offset,
                "limit": limit
            }
        }
    except Exception as e:
        logger.error(f"Failed to get scan logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/exploit-logs/{scan_id}/{exploit_filename}")
async def get_exploit_logs(scan_id: str, exploit_filename: str):
    """Get structured logs for a specific exploit."""
    try:
        from ml_engine.db_manager import DatabaseManager
        db = DatabaseManager()
        logs = db.get_exploit_logs(scan_id, exploit_filename)
        status = db.get_exploit_status(scan_id, exploit_filename)
        return {
            "success": True,
            "data": {
                "exploit_filename": exploit_filename,
                "scan_id": scan_id,
                "status": status,  # not_started | in_progress | completed | failed
                "logs": logs,
                "log_count": len(logs)
            }
        }
    except Exception as e:
        logger.error(f"Failed to get exploit logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/exploit-status/{scan_id}")
async def get_all_exploit_statuses(scan_id: str):
    """Get status of all exploits for a scan. Used to determine icon state in frontend."""
    try:
        from ml_engine.db_manager import DatabaseManager
        db = DatabaseManager()
        
        # Get all unique exploit filenames for this scan
        if not db.connected:
            return {"success": True, "data": {"statuses": {}}}
        
        collection = db.db['exploit_logs']
        exploit_filenames = collection.distinct('exploit_filename', {'scan_id': scan_id})
        
        statuses = {}
        for filename in exploit_filenames:
            statuses[filename] = db.get_exploit_status(scan_id, filename)
        
        return {
            "success": True,
            "data": {
                "scan_id": scan_id,
                "statuses": statuses  # {filename: status, ...}
            }
        }
    except Exception as e:
        logger.error(f"Failed to get exploit statuses: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan/{scan_id}/ready-exploits")
async def get_ready_exploits(scan_id: str):
    """
    Get all exploits that are ready for attack (generated during Stage 2).
    
    This enables real-time launching - exploits can be attacked individually
    as soon as they're generated, without waiting for Stage 2 to complete.
    """
    try:
        from ml_engine.db_manager import DatabaseManager
        db = DatabaseManager()
        
        if not db.connected:
            return {"success": True, "data": {"exploits": []}}
        
        # Get ready exploits from the exploit_ready collection
        exploits = db.get_ready_exploits(scan_id)
        
        return {
            "success": True,
            "data": {
                "scan_id": scan_id,
                "exploits": exploits,  # List of {filename, ready_for_attack, attack_launched, attack_status}
                "count": len(exploits)
            }
        }
    except Exception as e:
        logger.error(f"Failed to get ready exploits: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# --- Network Recon Endpoints ---

@router.post("/network/whitebox")
async def whitebox_workflow(request: WhiteboxWorkflowRequest):
    """
    Initiate whitebox exploitation workflow with attack mode.
    This starts a full scan with source code analysis, exploit generation,
    and optional auto-execution against the target.
    """
    try:
        if not os.path.isdir(request.source_path):
            raise HTTPException(status_code=400, detail="Source code directory does not exist")
        
        orchestrator = get_orchestrator()
        
        logger.info(f"Starting whitebox workflow: {request.application_name}")
        logger.info(f"  Target: {request.target_ip}:{request.target_port}")
        logger.info(f"  Attack Mode: {request.attack_mode}, Auto-Execute: {request.auto_execute}")
        
        # Start scan with attack mode and auto-execution enabled
        result = orchestrator.start_scan(
            target_dir=request.source_path,
            project_name=request.application_name,
            quick_scan=False,  # Full analysis for whitebox
            demo_mode=request.demo_mode,
            remote_host=request.target_ip if request.attack_mode else None,
            remote_port=int(request.target_port) if request.attack_mode else None,
            model="hermes",
            auto_execute=request.auto_execute
        )
        
        return {
            "success": True,
            "scan_id": result.get("scan_id"),
            "status": result.get("status", "pending"),
            "message": f"Whitebox scan started with attack mode={'enabled' if request.attack_mode else 'disabled'}"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start whitebox workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/network/scan")
async def scan_network_target(request: NetworkScanRequest):
    """Scan target IP for open ports and services, and save to database."""
    try:
        scanner = get_network_scanner()
        db = get_db()

        # Parse ports: "80,443" or "1-1000" or "" for auto-detect
        port_list = None  # None = nmap auto-detect (quick scan)
        if request.ports and request.ports.strip():
            if "-" in request.ports:
                start, end = request.ports.split("-")
                port_list = list(range(int(start), int(end) + 1))
            else:
                port_list = [int(p.strip()) for p in request.ports.split(",") if p.strip()]
        
        logger.info(f"Port scan mode: {'auto-detect (quick)' if port_list is None else f'{len(port_list)} ports'}")

        # Create a recon scan record in the database
        recon_scan_id = db.create_recon_scan(
            target_ip=request.target_ip,
            mode="network_scan",
            scan_name=request.application_name or f"Scan_{request.target_ip}"
        )
        logger.info(f"Created recon scan record: {recon_scan_id}")

        # Scan target - returns ScanResult with services and os_info
        scan_result = scanner.scan_target(request.target_ip, ports=port_list)

        # Convert ServiceInfo to dict (include protocol field)
        service_dicts = []
        for svc in scan_result.services:
            service_dicts.append({
                "port": svc.port,
                "protocol": svc.protocol,  # Include protocol for frontend display
                "state": "open",
                "service": svc.service,
                "product": svc.product,
                "version": svc.version,
                "banner": svc.banner
            })

        # Convert OSInfo to dict
        os_info_dict = {
            "name": scan_result.os_info.name,
            "accuracy": scan_result.os_info.accuracy,
            "family": scan_result.os_info.family,
            "vendor": scan_result.os_info.vendor,
            "os_gen": scan_result.os_info.os_gen
        }

        # Save services and OS info to database
        if recon_scan_id:
            db.update_recon_services(recon_scan_id, service_dicts, os_info_dict)
            db.complete_recon_scan(recon_scan_id)
            logger.info(f"Saved recon data to database: {len(service_dicts)} services")

        return {
            "scan_id": recon_scan_id,
            "services": service_dicts,
            "os_info": os_info_dict,
            "scan_time": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Network scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/network/analyze")
async def analyze_services(request: ServiceAnalysisRequest):
    """Analyze discovered services using LLM."""
    try:
        analyzer = get_service_analyzer()

        # Re-initialize if model changed
        if analyzer.model_id != request.model:
            global service_analyzer
            service_analyzer = None
            analyzer = get_service_analyzer()

        analysis_results = []
        for svc in request.services:
            analysis = analyzer.analyze_service(svc)
            formatted = analyzer.format_analysis(analysis)

            analysis_results.append({
                "port": analysis.port,
                "service": f"{analysis.service_name} {analysis.version}",
                "exploitation_steps": formatted,
                "source_links": analysis.source_code_links,
                "severity": analysis.risk_level,
                "cves": [cve.get("id", "") for cve in analysis.cves]
            })

        return {"analysis": analysis_results}
    except Exception as e:
        logger.error(f"Service analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class SimulationSetupRequest(BaseModel):
    service: Dict[str, Any]  # Service info (port, service, product, version, banner)
    os_info: Optional[Dict[str, Any]] = None  # OS detection info (name, family, vendor)


@router.post("/recon/simulation-setup")
async def generate_simulation_setup(request: SimulationSetupRequest):
    """Generate simulation/lab setup guide for a discovered service."""
    try:
        analyzer = get_service_analyzer()
        
        logger.info(f"Generating simulation setup for port {request.service.get('port')}")
        
        # Generate setup guide
        setup_data = analyzer.generate_simulation_setup(
            service_info=request.service,
            os_info=request.os_info
        )
        
        # Format for display
        formatted_guide = analyzer.format_simulation_setup(setup_data)
        
        return {
            "success": True,
            "setup_data": setup_data,
            "formatted_guide": formatted_guide
        }
    except Exception as e:
        logger.error(f"Simulation setup generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/network/blackbox")
async def blackbox_analysis(request: BlackboxAnalysisRequest):
    """Run blackbox exploitation analysis."""
    try:
        exploiter = get_blackbox_exploiter()

        # If services not provided, scan first
        services = request.services
        if not services:
            scanner = get_network_scanner()
            # Same logic as /network/scan: empty = auto-detect
            port_list = None
            if request.ports and request.ports.strip():
                if "-" in request.ports:
                    start, end = request.ports.split("-")
                    port_list = list(range(int(start), int(end) + 1))
                else:
                    port_list = [int(p.strip()) for p in request.ports.split(",") if p.strip()]

            scanned = scanner.scan_target(request.target_ip, ports=port_list)
            services = [{"port": s.port, "protocol": s.protocol, "service": s.service, "product": s.product, "version": s.version} for s in scanned.services]

        # Analyze each service
        results = []
        for svc in services:
            result = exploiter.analyze_service(svc, request.target_ip)
            formatted = exploiter.format_results(result)

            results.append({
                "port": result.port,
                "service": f"{result.service_name} {result.version}",
                "cve_matches": [{"cve_id": c.cve_id, "severity": c.severity, "cvss_score": c.cvss_score} for c in result.cves[:5]],
                "exploits": [{"exploit_id": e.exploit_id, "title": e.title, "url": e.url} for e in result.exploits[:3]],
                "fuzzing_results": {
                    "endpoints_tested": len(result.fuzzing_results),
                    "vulnerabilities_found": sum(1 for f in result.fuzzing_results if f.get("vulnerable")),
                    "interesting_paths": [f.get("payload") for f in result.fuzzing_results[:3] if f.get("vulnerable")]
                }
            })

        return {"results": results}
    except Exception as e:
        logger.error(f"Blackbox analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))




# ========== DATABASE MANAGEMENT ==========

@router.delete("/database/clear")
async def clear_database():
    """
    Clear all data from the database (scans, findings, exploits, logs).
    WARNING: This action is irreversible.
    """
    try:
        from ml_engine.db_manager import DatabaseManager
        
        db = DatabaseManager()
        
        if not db.connected:
            raise HTTPException(status_code=500, detail="Database not connected")
        
        success = db.clear_database()
        
        if success:
            logger.info("Database cleared successfully via API")
            return {
                "success": True,
                "message": "All scans, findings, and logs have been deleted."
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to clear database")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error clearing database: {e}")
        raise HTTPException(status_code=500, detail=str(e))

