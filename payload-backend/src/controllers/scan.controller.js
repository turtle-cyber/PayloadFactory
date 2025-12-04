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
      const scanConfig = {
        target_dir: extractedPath,
        project_name: applicationName || req.file.originalname.replace(".zip", ""),
        quick_scan: quickScan === "true" || quickScan === true,
        demo_mode: demoMode === "true" || demoMode === true,
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
}

export default new ScanController();
