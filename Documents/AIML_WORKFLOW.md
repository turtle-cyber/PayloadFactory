# AIML Workflow Technical Runbook

Last Updated: 2025-12-04  
Scope: End-to-end technical flow for the PayloadFactoryUX AIML pipeline (scan → classify → exploit → fuzz/optimize), including data artifacts, models, and control points.

## 1) End-to-End Flow (Happy Path)
- Trigger: Frontend uploads a ZIP to the Node backend → extracted into a temp folder → Python FastAPI `/start-scan` receives `target_dir` + flags (`quick_scan`, `demo_mode`, `model`, `remote_host/port`, `auto_execute`).
- Orchestrator (`server/app/scan_orchestrator.py`) writes a scan record to Mongo, sets `progress.current_stage=0`, then runs three Python stages in background subprocesses.
- Stage 1 (`scan_stage_1.py`): Specialized models (UnixCoder + GraphCodeBERT) scan C/C++/Java/PHP; outputs `intermediate_<scan_id>.json` and DB findings.
- Stage 2 (`scan_stage_2.py`): LLM analysis + exploit generation; writes `exploits/exploit_*.py` and `exploits/payloads/*.bin`; updates DB and status to `awaiting-selection`.
- Stage 3 (`scan_stage_3.py`): Fuzzing + RL optimization on selected exploits; optional auto-execution against `remote_host:remote_port`; finishes scan as `completed` or `failed`.

## 2) Stage 0 – Control & Orchestration
- Entry Points:
  - `POST /start-scan` (`server/app/api/routes.py`) → `ScanOrchestrator.start_scan()`.
  - `GET /scan-status/{scan_id}` for polling; `POST /stop-scan/{scan_id}` to cancel.
  - `POST /scan/{scan_id}/start-attack` resumes Stage 3 after user selects exploits (or `run_all`).
  - Whitebox attack shortcut: `POST /network/whitebox` (sets attack mode + auto-execute).
- State: Mongo `scans` document tracks status, stage index, file/vuln/exploit counters, and timestamps. `scan_logs` and `agent_logs` store streaming logs.
- Artifacts: `intermediate_<scan_id>.json` (deleted after use), `exploits/` output dir, `scan_log.json` on disk.

## 3) Stage 1 – Specialized Model Scanning (`scan_stage_1.py`)
- File discovery: walks `target_dir` for {`.c,.cpp,.cc,.h,.hpp,.java,.jsp,.php`}; filters tests/mocks/legacy, drops headers, and honors ignored dir/pattern lists.
- Optional quick mode: `FilePrioritizer` (`ml_engine/file_prioritizer.py`) scores and caps to `max_files` (default 300) using directory, filename, keyword, and size heuristics.
- Models: `VulnScanner` in `c_cpp` mode (`ml_engine/vuln_scanner.py`) loads fine-tuned/stock UnixCoder + GraphCodeBERT (4-bit not used here) on GPU/CPU. Removes comments, slides windows (1024 tokens, stride 512), runs both models, averages scores, and requires dangerous-function context for mid-tier scores.
- Classification: Pattern-based CWE/OWASP mapping via `CVEDatabase.classify_with_fallback()` (`ml_engine/cve_database.py`), plus version-based Tomcat CVE hints (parses `build.properties.default`).
- Outputs per finding: file path, line estimate, vulnerable chunk, CWE/type/severity, confidence, model consensus. Deduplicates overlapping windows.
- Persistence: `DatabaseManager.save_finding()` stores `findings` (and increments scan stats); `db_manager.save_scan_log()` streams progress. Writes `intermediate_<scan_id>.json` for Stage 2 handoff.

## 4) Stage 2 – LLM Analysis & Exploit Generation (`scan_stage_2.py`)
- Inputs: Stage 1 findings + optionally other languages {`.py,.php,.java,.js,.go,.rb`} unless `--skip-other-files`.
- Modes: `demo_mode` whitelists critical Tomcat files for paranoid scanning; `model` flag switches LLM (default from `ml_engine/model_config.py`, e.g., Hermes/Qwen).
- LLM loading: `VulnScanner` in `llm` mode loads causal LM with 4-bit `BitsAndBytesConfig`; optional LoRA adapter if present.
- Context extraction: `extract_vulnerability_context()` builds structured context (CWE, chunk, function, protocol, offsets, architecture).
- Exploit generation: `ExploitGenerator.generate_exploit_enhanced()` reuses the loaded model/tokenizer to avoid double VRAM usage; routes prompt by CWE/filetype; embeds `remote_host/port` into URLs if provided.
- Validation: `ExploitValidator` checks syntax (AST), imports (pwntools/requests), structure (connection/payload/send), dangerous patterns. Non-blocking warnings are logged; fatal syntax issues mark exploit invalid.
- Artifacts: `exploits/exploit_<n>.py`, binary payloads under `exploits/payloads/`, optional saved context. DB updates: `save_exploit()` nests exploits under findings; progress counters increment `exploits_generated`.
- Exit state: Sets scan status to `awaiting-selection`; Stage 3 is triggered later via `/scan/{scan_id}/start-attack`.

## 5) Stage 3 – Fuzzing & RL Optimization (`scan_stage_3.py`)
- Target set: All `exploit_*.py` or user-selected list. Supports offline simulation or live attack (`remote_host/port`).
- Fuzz engines:
  - Default `Fuzzer` (`ml_engine/fuzzing_module.py`): random + structured mutations; CVE-specific Tomcat payload banks; endpoint list from embedded exploit metadata or default web paths.
  - `SmartHybridFuzzer` when `--smart-fuzz` and remote target: 3-layer pipeline (random mutation → Boofuzz engine → LLM-guided refinement).
  - `BoofuzzEngine` fallback if `--use-boofuzz`.
- RL loop: `RLAgent` (`ml_engine/rl_agent.py`) with Q-learning, epsilon decay, repeat-penalty, CVE action cycling, and feedback-biased action selection. Mutations include web (SQLi/XSS/PathTraversal/EL) and binary (offset/ROP/NOP) strategies.
- Feedback: `FeedbackContext` merges socket responses (codes/latency/errors) with remote agent crash logs (`/agent/logs`) pulled from Mongo; rewards RCE > crash > blocked.
- Auto-execution: If `--auto-execute` and `remote_host` provided, `ExploitExecutor` runs exploits with timeout, captures success, and logs to DB.
- Outputs: Updated payload binaries, confirmed crashes/RCE logs, optional exploit code updates (if RCE confirmed), DB `scan_logs` entries, final scan status.

## 6) Supporting Modules
- Recon & service analysis: `network_scanner.py` (nmap wrapper), `service_analyzer.py` (LLM risk assessment + simulation guides), `blackbox_exploitation.py` (CVE/ExploitDB lookup + light fuzzing). Exposed via `/network/scan`, `/network/analyze`, `/network/blackbox`.
- Patch generation: `patch_generator.py` and `/patch` endpoint for remediation suggestions (LLM-driven).
- Training: `ml_engine/train.py` for classifier fine-tuning (CodeBERT/UnixCoder/GraphCodeBERT) with CSV datasets; `train_llm.py`/`train_multilang.py` for LoRA fine-tunes referenced in `model_config.py`.
- Logging & telemetry: `ml_engine/logger_config.py` standardizes JSON logs; `scan_log.json` mirrors DB logs for UI streaming.

## 7) Data & Artifacts
- On disk: `intermediate_<scan_id>.json` (Stage 1 findings), `exploits/` + `exploits/payloads/`, `scan_log.json`, optional `boofuzz-results/`.
- Mongo collections (when connected): `scans`, `findings` (with nested `exploits`), `scan_logs`, `agent_logs`, `recon_scans`.
- Remote agent: `linux_agent.py` posts system/app log hits to `/agent/logs` with metadata for crash correlation.

## 8) Control Flags & Operational Notes
- `quick_scan`: limits Stage 1 files and skips Stage 2 “other files” unless critical demo targets are found.
- `demo_mode`: aggressive LLM scanning of Tomcat hotspot files; keeps skip-other-files safety but overrides for critical paths.
- `auto_execute`: passes through to Stage 3 to run exploits post-fuzzing against the provided host/port.
- Failure handling: Stage subprocess non-zero exits mark scan `failed`; orchestrator cleans intermediate JSON but preserves logs/exploits. Cancellation flips status to `cancelled`.

## 9) How to Run (API-first)
```bash
# Start scan (whitebox attack enabled)
curl -X POST http://localhost:8000/start-scan \
  -H "Content-Type: application/json" \
  -d '{"target_dir":"/tmp/project","project_name":"Demo","quick_scan":false,"demo_mode":false,"remote_host":"10.0.0.5","remote_port":8080,"model":"hermes","auto_execute":true}'

# Poll status
curl http://localhost:8000/scan-status/<scan_id>

# Resume Stage 3 with selected exploits
curl -X POST http://localhost:8000/scan/<scan_id>/start-attack \
  -H "Content-Type: application/json" \
  -d '{"selected_exploits":["exploit_1.py","exploit_3.py"],"run_all":false}'
```

## 10) What to Read Next
- Frontend/Node integration flow: `IMPLEMENTATION_SUMMARY.md`.
- Fuzzer internals and feedback loop visuals: `FuzzingWorkFlow.md`.
- Developer deep dive and model inventory: `Documents/DEVELOPER_DOCUMENTATION.md`.

