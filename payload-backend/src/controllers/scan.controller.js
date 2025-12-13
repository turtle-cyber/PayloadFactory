import scanService from "../services/scan.service.js";
import { HTTP_STATUS } from "../config/constants.js";
import { logger } from "../utils/logger.js";
import pythonBridge from "../services/python-bridge.service.js";
import fs from "fs";
import path from "path";
import os from "os";
import AdmZip from "adm-zip";

/**
 * Controller for scan-related endpoints
 */
class ScanController {
  /**
   * Get all scans
   * @route GET /api/scans
   */
  async getAllScans(req, res, next) {
    try {
      logger.info("Fetching all scans");

      const result = await scanService.getAllScans();

      logger.info(`Successfully fetched ${result["scan-count"]} scans`);

      return res.status(HTTP_STATUS.OK).json(result);
    } catch (error) {
      logger.error("Error fetching scans", { error: error.message });
      next(error);
    }
  }

  /**
   * Get a single scan by ID
   * @route GET /api/scans/:id
   */
  async getScanById(req, res, next) {
    try {
      const { id } = req.params;

      logger.info(`Fetching scan with ID: ${id}`);

      const result = await scanService.getScanById(id);

      if (!result) {
        return res.status(HTTP_STATUS.NOT_FOUND).json({
          success: false,
          message: "Scan not found",
        });
      }

      logger.info(`Successfully fetched scan with ID: ${id}`);

      return res.status(HTTP_STATUS.OK).json(result);
    } catch (error) {
      logger.error(`Error fetching scan with ID: ${req.params.id}`, {
        error: error.message,
      });
      next(error);
    }
  }

  /**
   * Upload and start a new scan
   * @route POST /api/scans/upload
   */
  async uploadAndScan(req, res, next) {
    let extractedPath = null;

    try {
      // Validate file upload
      if (!req.file) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "No file uploaded. Please upload a ZIP file.",
        });
      }

      const {
        applicationName,
        maxTokenLength,
        batchSize,
        minConfidence,
        quickScan,
        demoMode,
        attackMode,
        targetIp,
        targetPort,
        autoExec,
      } = req.body;

      logger.info("Processing ZIP upload", {
        filename: req.file.originalname,
        size: req.file.size,
        applicationName,
      });

      // Validate ZIP file
      if (!req.file.originalname.toLowerCase().endsWith(".zip")) {
        // Clean up uploaded file
        fs.unlinkSync(req.file.path);
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "Invalid file type. Please upload a ZIP file.",
        });
      }

      // Create a unique directory for extraction
      const timestamp = Date.now();
      const extractDir = path.join(
        os.tmpdir(),
        "payload-scans",
        `scan_${timestamp}`
      );

      // Ensure parent directory exists
      fs.mkdirSync(path.dirname(extractDir), { recursive: true });

      // Extract ZIP file
      logger.info("Extracting ZIP file", { path: extractDir });
      const zip = new AdmZip(req.file.path);
      zip.extractAllTo(extractDir, true);

      extractedPath = extractDir;

      // Clean up the uploaded ZIP file
      fs.unlinkSync(req.file.path);

      // Prepare scan configuration for Python backend
      const isAttackMode = attackMode === "true" || attackMode === true;
      const scanConfig = {
        target_dir: extractedPath,
        project_name: applicationName || req.file.originalname.replace(".zip", ""),
        quick_scan: quickScan === "true" || quickScan === true,
        demo_mode: demoMode === "true" || demoMode === true,
        attack_mode: isAttackMode,
        remote_host: isAttackMode ? targetIp : undefined,
        remote_port: isAttackMode ? parseInt(targetPort, 10) : undefined,
        auto_execute: isAttackMode && (autoExec === "true" || autoExec === true),
      };

      logger.info("Starting scan via Python backend", { config: scanConfig });

      // Start scan via Python backend
      const scanResult = await pythonBridge.startScan(scanConfig);

      if (!scanResult.success) {
        throw new Error("Failed to start scan");
      }

      logger.info("Scan started successfully", {
        scan_id: scanResult.data.scan_id,
      });

      return res.status(HTTP_STATUS.OK).json({
        success: true,
        message: "Scan started successfully",
        scan_id: scanResult.data.scan_id,
        status: scanResult.data.status,
      });
    } catch (error) {
      logger.error("Error processing scan upload", { error: error.message });

      // Clean up on error
      if (req.file && fs.existsSync(req.file.path)) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (cleanupError) {
          logger.error("Failed to cleanup uploaded file", {
            error: cleanupError.message,
          });
        }
      }

      if (extractedPath && fs.existsSync(extractedPath)) {
        try {
          fs.rmSync(extractedPath, { recursive: true, force: true });
        } catch (cleanupError) {
          logger.error("Failed to cleanup extracted files", {
            error: cleanupError.message,
          });
        }
      }

      next(error);
    }
  }

  /**
   * Get scan progress/status
   * @route GET /api/scans/:id/status
   */
  async getScanStatus(req, res, next) {
    try {
      const { id } = req.params;

      logger.debug("Fetching scan status", { scan_id: id });

      // Get status from Python backend
      const statusResult = await pythonBridge.getScanStatus(id);

      if (!statusResult.success) {
        return res.status(HTTP_STATUS.NOT_FOUND).json({
          success: false,
          message: statusResult.error || "Scan not found",
        });
      }

      return res.status(HTTP_STATUS.OK).json({
        success: true,
        data: statusResult.data,
      });
    } catch (error) {
      logger.error("Error fetching scan status", {
        scan_id: req.params.id,
        error: error.message,
      });
      next(error);
    }
  }

  /**
   * Stop a running scan
   * @route POST /api/scans/:id/stop
   */
  async stopScan(req, res, next) {
    try {
      const { id } = req.params;

      logger.info("Stopping scan", { scan_id: id });

      const stopResult = await pythonBridge.stopScan(id);

      if (!stopResult.success) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: stopResult.error || "Failed to stop scan",
        });
      }

      return res.status(HTTP_STATUS.OK).json({
        success: true,
        message: "Scan stopped successfully",
        data: stopResult.data,
      });
    } catch (error) {
      logger.error("Error stopping scan", {
        scan_id: req.params.id,
        error: error.message,
      });
      next(error);
    }
  }

  /**
   * Clear all scans and findings from database
   * @route DELETE /api/scans/all
   */
  async clearDatabase(req, res, next) {
    try {
      logger.info("Clearing database - all scans and findings");

      // Call Python backend to clear database
      const axios = (await import("axios")).default;
      const pythonUrl = process.env.PYTHON_API_URL || "http://localhost:8000";

      const response = await axios.delete(`${pythonUrl}/database/clear`);

      if (response.data.success) {
        logger.info("Database cleared successfully");
        return res.status(HTTP_STATUS.OK).json({
          success: true,
          message: "Database cleared successfully. All scans and findings have been deleted.",
        });
      } else {
        throw new Error(response.data.message || "Failed to clear database");
      }
    } catch (error) {
      logger.error("Error clearing database", { error: error.message });
      
      // If Python backend is unavailable, return error
      return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
        success: false,
        message: error.response?.data?.detail || error.message || "Failed to clear database",
      });
    }
  }

  /**
   * Start attack with selected exploits (Resume Stage 3)
   * @route POST /api/scans/:id/start-attack
   */
  async startAttack(req, res, next) {
    try {
      const { id } = req.params;
      const { selected_exploits = [], run_all = false } = req.body;

      logger.info("Starting attack with selected exploits", {
        scan_id: id,
        selected_count: selected_exploits.length,
        run_all,
      });

      // Validate input
      if (!run_all && (!selected_exploits || selected_exploits.length === 0)) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "No exploits selected. Please select at least one exploit or set run_all to true.",
        });
      }

      const attackResult = await pythonBridge.startAttack(id, {
        selected_exploits,
        run_all,
      });

      if (!attackResult.success) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: attackResult.error || "Failed to start attack",
        });
      }

      logger.info("Attack started successfully", {
        scan_id: id,
        status: attackResult.data.status,
      });

      return res.status(HTTP_STATUS.OK).json({
        success: true,
        message: attackResult.data.message || "Attack started successfully",
        data: attackResult.data,
      });
    } catch (error) {
      logger.error("Error starting attack", {
        scan_id: req.params.id,
        error: error.message,
      });
      next(error);
    }
  }

  /**
   * Get structured logs for a specific exploit
   * @route GET /api/scans/:id/exploit-logs/:exploit_filename
   */
  async getExploitLogs(req, res, next) {
    try {
      const { id, exploit_filename } = req.params;

      const result = await pythonBridge.getExploitLogs(id, exploit_filename);

      if (!result.success) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: result.error || "Failed to get exploit logs",
        });
      }

      return res.status(HTTP_STATUS.OK).json({
        success: true,
        data: result.data,
      });
    } catch (error) {
      logger.error("Error getting exploit logs", {
        scan_id: req.params.id,
        exploit: req.params.exploit_filename,
        error: error.message,
      });
      next(error);
    }
  }

  /**
   * Get status of all exploits for a scan
   * @route GET /api/scans/:id/exploit-statuses
   */
  async getExploitStatuses(req, res, next) {
    try {
      const { id } = req.params;

      const result = await pythonBridge.getExploitStatuses(id);

      if (!result.success) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: result.error || "Failed to get exploit statuses",
        });
      }

      return res.status(HTTP_STATUS.OK).json({
        success: true,
        data: result.data,
      });
    } catch (error) {
      logger.error("Error getting exploit statuses", {
        scan_id: req.params.id,
        error: error.message,
      });
      next(error);
    }
  }
}

export default new ScanController();
