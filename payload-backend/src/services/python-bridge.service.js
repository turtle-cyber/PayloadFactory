import axios from "axios";
import { logger } from "../utils/logger.js";

/**
 * Service to communicate with the Python FastAPI backend
 */
class PythonBridgeService {
  constructor() {
    // Python FastAPI server URL (from environment or default)
    this.pythonApiUrl =
      process.env.PYTHON_API_URL || "http://localhost:8000";
    this.axiosInstance = axios.create({
      baseURL: this.pythonApiUrl,
      timeout: 30000, // 30 second timeout for initial requests
      headers: {
        "Content-Type": "application/json",
      },
    });
  }

  /**
   * Start a new scan via Python backend
   * @param {Object} scanConfig - Scan configuration
   * @param {string} scanConfig.target_dir - Path to the extracted project directory
   * @param {string} scanConfig.project_name - Name of the project
   * @param {boolean} scanConfig.quick_scan - Whether to run a quick scan
   * @param {boolean} scanConfig.demo_mode - Whether to run in demo mode
   * @param {string} scanConfig.remote_host - Optional remote host to target
   * @param {number} scanConfig.remote_port - Optional remote port to target
   * @returns {Promise<Object>} Response with scan_id and status
   */
  async startScan(scanConfig) {
    try {
      logger.info("Starting scan via Python backend", { config: scanConfig });

      const response = await this.axiosInstance.post(
        "/start-scan",
        scanConfig
      );

      logger.info("Scan started successfully", {
        scan_id: response.data.scan_id,
      });

      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      logger.error("Failed to start scan", {
        error: error.message,
        response: error.response?.data,
      });

      throw new Error(
        error.response?.data?.detail ||
          error.message ||
          "Failed to start scan"
      );
    }
  }

  /**
   * Get the current status of a scan
   * @param {string} scanId - The scan ID
   * @returns {Promise<Object>} Scan status and progress
   */
  async getScanStatus(scanId) {
    try {
      logger.debug("Fetching scan status", { scan_id: scanId });

      const response = await this.axiosInstance.get(
        `/scan-status/${scanId}`
      );

      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      logger.error("Failed to get scan status", {
        scan_id: scanId,
        error: error.message,
        response: error.response?.data,
      });

      // If scan not found, return a structured error
      if (error.response?.status === 404) {
        return {
          success: false,
          error: "Scan not found",
          scan_id: scanId,
        };
      }

      throw new Error(
        error.response?.data?.detail ||
          error.message ||
          "Failed to get scan status"
      );
    }
  }

  /**
   * Stop a running scan
   * @param {string} scanId - The scan ID to stop
   * @returns {Promise<Object>} Response indicating success or failure
   */
  async stopScan(scanId) {
    try {
      logger.info("Stopping scan", { scan_id: scanId });

      const response = await this.axiosInstance.post(`/stop-scan/${scanId}`);

      logger.info("Scan stopped successfully", { scan_id: scanId });

      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      logger.error("Failed to stop scan", {
        scan_id: scanId,
        error: error.message,
        response: error.response?.data,
      });

      throw new Error(
        error.response?.data?.detail ||
          error.message ||
          "Failed to stop scan"
      );
    }
  }

  /**
   * Check if the Python backend is healthy
   * @returns {Promise<boolean>} True if healthy, false otherwise
   */
  async checkHealth() {
    try {
      const response = await this.axiosInstance.get("/health");
      return response.data.status === "healthy";
    } catch (error) {
      logger.error("Python backend health check failed", {
        error: error.message,
      });
      return false;
    }
  }

  /**
   * Scan network target for open ports and services
   * @param {Object} scanConfig - Network scan configuration
   * @param {string} scanConfig.target_ip - Target IP address
   * @param {string} scanConfig.ports - Ports to scan (e.g., "80,443" or "1-1000")
   * @param {string} scanConfig.application_name - Name of the target application
   * @returns {Promise<Object>} Discovered services
   */
  async scanNetwork(scanConfig) {
    try {
      logger.info("Starting network scan via Python backend", {
        config: scanConfig,
      });

      const response = await this.axiosInstance.post(
        "/network/scan",
        scanConfig,
        {
          timeout: 300000, // 5 minutes for network scans with OS detection
        }
      );

      logger.info("Network scan completed", {
        services_found: response.data.services?.length || 0,
      });

      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      logger.error("Failed to scan network", {
        error: error.message,
        response: error.response?.data,
      });

      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.message ||
          "Failed to scan network",
      };
    }
  }

  /**
   * Analyze discovered services using LLM
   * @param {Object} analysisConfig - Analysis configuration
   * @param {Array} analysisConfig.services - Array of service objects
   * @param {string} analysisConfig.model - LLM model to use (default: "hermes")
   * @returns {Promise<Object>} Analysis results
   */
  async analyzeServices(analysisConfig) {
    try {
      logger.info("Starting service analysis via Python backend", {
        service_count: analysisConfig.services?.length || 0,
        model: analysisConfig.model,
      });

      const response = await this.axiosInstance.post(
        "/network/analyze",
        analysisConfig,
        {
          timeout: 180000, // 3 minutes for LLM analysis
        }
      );

      logger.info("Service analysis completed", {
        analysis_count: response.data.analysis?.length || 0,
      });

      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      logger.error("Failed to analyze services", {
        error: error.message,
        response: error.response?.data,
      });

      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.message ||
          "Failed to analyze services",
      };
    }
  }

  /**
   * Run blackbox exploitation analysis
   * @param {Object} blackboxConfig - Blackbox analysis configuration
   * @param {string} blackboxConfig.target_ip - Target IP address
   * @param {string} blackboxConfig.ports - Ports to analyze
   * @param {Array} blackboxConfig.services - Pre-discovered services (optional)
   * @returns {Promise<Object>} Blackbox analysis results
   */
  async blackboxAnalysis(blackboxConfig) {
    try {
      logger.info("Starting blackbox analysis via Python backend", {
        target_ip: blackboxConfig.target_ip,
      });

      const response = await this.axiosInstance.post(
        "/network/blackbox",
        blackboxConfig,
        {
          timeout: 300000, // 5 minutes for blackbox analysis
        }
      );

      logger.info("Blackbox analysis completed", {
        results_count: response.data.results?.length || 0,
      });

      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      logger.error("Failed to run blackbox analysis", {
        error: error.message,
        response: error.response?.data,
      });

      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.message ||
          "Failed to run blackbox analysis",
      };
    }
  }

  /**
   * Initiate whitebox exploitation workflow
   * @param {Object} whiteboxConfig - Whitebox workflow configuration
   * @param {string} whiteboxConfig.source_path - Path to source code
   * @param {string} whiteboxConfig.target_ip - Target IP address
   * @param {string} whiteboxConfig.target_port - Target port
   * @param {string} whiteboxConfig.application_name - Application name
   * @returns {Promise<Object>} Scan ID and status
   */
  async whiteboxWorkflow(whiteboxConfig) {
    try {
      logger.info("Starting whitebox workflow via Python backend", {
        source_path: whiteboxConfig.source_path,
        target_ip: whiteboxConfig.target_ip,
      });

      const response = await this.axiosInstance.post(
        "/network/whitebox",
        whiteboxConfig
      );

      logger.info("Whitebox workflow initiated", {
        scan_id: response.data.scan_id,
      });

      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      logger.error("Failed to start whitebox workflow", {
        error: error.message,
        response: error.response?.data,
      });

      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.message ||
          "Failed to start whitebox workflow",
      };
    }
  }

  /**
   * Start attack with selected exploits (Resume Stage 3)
   * @param {string} scanId - The scan ID to resume
   * @param {Object} attackConfig - Attack configuration
   * @param {Array} attackConfig.selected_exploits - List of exploit filenames to run
   * @param {boolean} attackConfig.run_all - If true, run all exploits
   * @returns {Promise<Object>} Response with status
   */
  async startAttack(scanId, attackConfig) {
    try {
      logger.info("Starting attack with selected exploits via Python backend", {
        scan_id: scanId,
        selected_count: attackConfig.selected_exploits?.length || 0,
        run_all: attackConfig.run_all,
      });

      const response = await this.axiosInstance.post(
        `/scan/${scanId}/start-attack`,
        attackConfig,
        {
          timeout: 60000, // 1 minute for attack initiation
        }
      );

      logger.info("Attack started successfully", {
        scan_id: scanId,
        status: response.data.status,
      });

      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      logger.error("Failed to start attack", {
        scan_id: scanId,
        error: error.message,
        response: error.response?.data,
      });

      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.message ||
          "Failed to start attack",
      };
    }
  }

  /**
   * Get structured logs for a specific exploit
   * @param {string} scanId - The scan ID
   * @param {string} exploitFilename - Name of the exploit file
   * @returns {Promise<Object>} Exploit logs and status
   */
  async getExploitLogs(scanId, exploitFilename) {
    try {
      logger.debug("Fetching exploit logs", {
        scan_id: scanId,
        exploit: exploitFilename,
      });

      const response = await this.axiosInstance.get(
        `/exploit-logs/${scanId}/${encodeURIComponent(exploitFilename)}`
      );

      return {
        success: true,
        data: response.data.data,
      };
    } catch (error) {
      logger.error("Failed to get exploit logs", {
        scan_id: scanId,
        exploit: exploitFilename,
        error: error.message,
      });

      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.message ||
          "Failed to get exploit logs",
      };
    }
  }

  /**
   * Get status of all exploits for a scan
   * @param {string} scanId - The scan ID
   * @returns {Promise<Object>} Map of exploit filename to status
   */
  async getExploitStatuses(scanId) {
    try {
      const response = await this.axiosInstance.get(
        `/exploit-status/${scanId}`
      );

      return {
        success: true,
        data: response.data.data,
      };
    } catch (error) {
      logger.error("Failed to get exploit statuses", {
        scan_id: scanId,
        error: error.message,
      });

      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.message ||
          "Failed to get exploit statuses",
      };
    }
  }
}

export default new PythonBridgeService();
