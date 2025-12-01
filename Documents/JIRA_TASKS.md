# Jira Task List: PayloadFactoryUX

## Epic 1: Reconnaissance Module
**Goal**: Automate target analysis and source code acquisition.

*   **Task 1.1: Implement HTTP Header & Server Analysis**
    *   **Description**: Develop functionality to inspect HTTP headers, identify server versions, and detect OS fingerprints.
    *   **Acceptance Criteria**: Script correctly identifies server/OS from headers.
*   **Task 1.2: Develop Attack Surface Mapper**
    *   **Description**: Create a scanner to map potential entry points and exposed files (e.g., `.git`, backups) on the target.
    *   **Acceptance Criteria**: Scanner lists exposed sensitive files without external dependencies.
*   **Task 1.3: Implement Automated Source Code Retrieval**
    *   **Description**: Automate the download of source code if exposed via `.zip`, `.tar.gz`, or `.git` on the target.
    *   **Acceptance Criteria**: System successfully downloads and extracts exposed source archives.
*   **Task 1.4: Implement Manual Source Code Input**
    *   **Description**: Create a fallback mechanism for users to manually upload or paste source code.
    *   **Acceptance Criteria**: User can upload a zip/text file, and the system processes it for scanning.

## Epic 2: Vulnerability Detection Engine
**Goal**: Detect security flaws in source code using ML models.

*   **Task 2.1: Integrate UnixCoder Model**
    *   **Description**: Load and integrate the fine-tuned UnixCoder model for C/C++ vulnerability detection.
    *   **Acceptance Criteria**: Model accepts code snippets and outputs vulnerability probability.
*   **Task 2.2: Integrate GraphCodeBERT Model**
    *   **Description**: Load and integrate GraphCodeBERT for semantic analysis and data flow vulnerability detection.
    *   **Acceptance Criteria**: Model runs alongside UnixCoder and provides a consensus score.
*   **Task 2.3: Implement Scanner Logic & Reporting**
    *   **Description**: Develop the main scanner logic to process files, invoke models, and aggregate results with CWE/CVE tags.
    *   **Acceptance Criteria**: Scanner outputs a JSON report with file paths, line numbers, severity, and CWE IDs.

## Epic 3: Exploit Generation Core
**Goal**: Generate functional exploit scripts using LLM.

*   **Task 3.1: Setup Hermes 3 8B with QLoRA**
    *   **Description**: Configure the Hermes 3 8B model with 4-bit quantization (QLoRA) to fit in 12GB VRAM.
    *   **Acceptance Criteria**: Model loads successfully on the target GPU without OOM errors.
*   **Task 3.2: Develop Prompt Engineering Template**
    *   **Description**: Create optimized system prompts to guide the LLM in generating Python exploit scripts based on vulnerability reports.
    *   **Acceptance Criteria**: LLM generates syntactically correct Python code for a given vulnerability.
*   **Task 3.3: Implement Exploit Generation Pipeline**
    *   **Description**: Connect the Vulnerability Scanner output to the LLM to trigger automatic exploit generation.
    *   **Acceptance Criteria**: Pipeline takes a vulnerability report and outputs a Python exploit script.

## Epic 4: Fuzzing & Verification
**Goal**: Validate exploits and stress-test targets.

*   **Task 4.1: Develop Mutation Fuzzer**
    *   **Description**: Build a mutation-based fuzzer (bit flips, byte injection) to modify payloads.
    *   **Acceptance Criteria**: Fuzzer generates variations of an input payload.
*   **Task 4.2: Implement Crash Detection & Logging**
    *   **Description**: Create a monitor to detect application crashes or successful exploit indicators.
    *   **Acceptance Criteria**: System logs a "Success" event when a target crashes or returns a specific flag.
*   **Task 4.3: Integrate Exploit Verification**
    *   **Description**: Automate the execution of generated exploits against the target.
    *   **Acceptance Criteria**: System runs the script and captures the exit code/output.

## Epic 5: Reinforcement Learning Optimization
**Goal**: Optimize payloads for higher success rates.

*   **Task 5.1: Implement Q-Learning Agent**
    *   **Description**: Develop an RL agent using Q-Learning to optimize payload parameters (length, padding).
    *   **Acceptance Criteria**: Agent updates its Q-table based on feedback (Crash/No Crash).
*   **Task 5.2: Integrate RL Feedback Loop**
    *   **Description**: Connect the Fuzzer output to the RL agent to enable continuous learning during a session.
    *   **Acceptance Criteria**: Agent improves success rate over multiple iterations.

## Epic 6: Backend & UI
**Goal**: Provide a user-friendly interface and orchestration.

*   **Task 6.1: Develop FastAPI Backend**
    *   **Description**: Create REST API endpoints for `/recon`, `/scan`, `/generate`, and `/fuzz`.
    *   **Acceptance Criteria**: API accepts requests and triggers the corresponding ML engine modules.
*   **Task 6.2: Build Dashboard UI**
    *   **Description**: Create a frontend dashboard to visualize scan results, vulnerability reports, and exploit status.
    *   **Acceptance Criteria**: User can view a list of vulnerabilities and download generated exploits.
*   **Task 6.3: Implement Scan Configuration Interface**
    *   **Description**: Create UI forms for users to input Target URL, upload source code, and configure scan settings.
    *   **Acceptance Criteria**: User inputs are correctly passed to the backend API.
