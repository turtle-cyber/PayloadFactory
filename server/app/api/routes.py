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
