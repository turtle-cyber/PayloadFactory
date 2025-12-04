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
}

export default new PythonBridgeService();
