import { HTTP_STATUS } from "../config/constants.js";
import { logger } from "../utils/logger.js";
import pythonBridge from "../services/python-bridge.service.js";
import fs from "fs";
import path from "path";
import os from "os";
import AdmZip from "adm-zip";

/**
 * Controller for network reconnaissance endpoints
 */
class ReconController {
  /**
   * Scan network target for services
   * @route POST /api/recon/scan
   */
  async scanNetwork(req, res, next) {
    try {
      const { target_ip, ports, application_name } = req.body;

      // Validate input
      if (!target_ip || !target_ip.trim()) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "Target IP is required",
        });
      }

      logger.info("Starting network scan", {
        target_ip,
        ports,
        application_name,
      });

      // Call Python backend for network scanning
      const scanResult = await pythonBridge.scanNetwork({
        target_ip: target_ip.trim(),
        ports: ports || "21,22,80,443,3306,8080",
        application_name: application_name || "Unknown Target",
      });

      if (!scanResult.success) {
        return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
          success: false,
          message: scanResult.error || "Network scan failed",
        });
      }

      logger.info("Network scan completed", {
        target_ip,
        services_found: scanResult.data.services.length,
      });

      return res.status(HTTP_STATUS.OK).json({
        success: true,
        message: "Network scan completed successfully",
        data: {
          target_ip,
          services: scanResult.data.services,
          scan_time: scanResult.data.scan_time,
        },
      });
    } catch (error) {
      logger.error("Error during network scan", {
        error: error.message,
        target_ip: req.body.target_ip,
      });
      next(error);
    }
  }

  /**
   * Analyze discovered services using LLM
   * @route POST /api/recon/analyze
   */
  async analyzeServices(req, res, next) {
    try {
      const { services, model } = req.body;

      // Validate input
      if (!services || !Array.isArray(services) || services.length === 0) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "Services array is required and must not be empty",
        });
      }

      logger.info("Starting LLM analysis", {
        service_count: services.length,
        model: model || "hermes",
      });

      // Call Python backend for LLM analysis
      const analysisResult = await pythonBridge.analyzeServices({
        services,
        model: model || "hermes",
      });

      if (!analysisResult.success) {
        return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
          success: false,
          message: analysisResult.error || "Analysis failed",
        });
      }

      logger.info("LLM analysis completed", {
        service_count: services.length,
        analysis_count: analysisResult.data.analysis.length,
      });

      return res.status(HTTP_STATUS.OK).json({
        success: true,
        message: "Service analysis completed successfully",
        data: {
          analysis: analysisResult.data.analysis,
        },
      });
    } catch (error) {
      logger.error("Error during service analysis", {
        error: error.message,
      });
      next(error);
    }
  }

  /**
   * Run blackbox exploitation analysis
   * @route POST /api/recon/blackbox
   */
  async blackboxAnalysis(req, res, next) {
    try {
      const { target_ip, ports, services } = req.body;

      // Validate input
      if (!target_ip || !target_ip.trim()) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "Target IP is required",
        });
      }

      logger.info("Starting blackbox analysis", {
        target_ip,
        ports,
        service_count: services?.length || 0,
      });

      // Call Python backend for blackbox analysis
      const blackboxResult = await pythonBridge.blackboxAnalysis({
        target_ip: target_ip.trim(),
        ports: ports || "21,22,80,443,3306,8080",
        services: services || [],
      });

      if (!blackboxResult.success) {
        return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
          success: false,
          message: blackboxResult.error || "Blackbox analysis failed",
        });
      }

      logger.info("Blackbox analysis completed", {
        target_ip,
        results_count: blackboxResult.data.results.length,
      });

      return res.status(HTTP_STATUS.OK).json({
        success: true,
        message: "Blackbox analysis completed successfully",
        data: {
          results: blackboxResult.data.results,
        },
      });
    } catch (error) {
      logger.error("Error during blackbox analysis", {
        error: error.message,
        target_ip: req.body.target_ip,
      });
      next(error);
    }
  }

  /**
   * Initiate whitebox exploitation workflow
   * @route POST /api/recon/whitebox
   */
  async whiteboxWorkflow(req, res, next) {
    try {
      const { source_path, target_ip, target_port, application_name } =
        req.body;

      // Validate input
      if (!source_path || !source_path.trim()) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "Source code path is required for whitebox mode",
        });
      }

      if (!target_ip || !target_ip.trim()) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "Target IP is required",
        });
      }

      logger.info("Starting whitebox workflow", {
        source_path,
        target_ip,
        target_port,
        application_name,
      });

      // Call Python backend to start whitebox scan
      const whiteboxResult = await pythonBridge.whiteboxWorkflow({
        source_path: source_path.trim(),
        target_ip: target_ip.trim(),
        target_port: target_port || "80",
        application_name: application_name || "Whitebox Target",
      });

      if (!whiteboxResult.success) {
        return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
          success: false,
          message: whiteboxResult.error || "Whitebox workflow failed",
        });
      }

      logger.info("Whitebox workflow initiated", {
        scan_id: whiteboxResult.data.scan_id,
      });

      return res.status(HTTP_STATUS.OK).json({
        success: true,
        message: "Whitebox scan initiated successfully",
        data: {
          scan_id: whiteboxResult.data.scan_id,
          status: whiteboxResult.data.status,
          redirect_to_scan: true,
        },
      });
    } catch (error) {
      logger.error("Error during whitebox workflow", {
        error: error.message,
        source_path: req.body.source_path,
      });
      next(error);
    }
  }

  /**
   * Upload ZIP and initiate whitebox exploitation workflow
   * @route POST /api/recon/whitebox/upload
   */
  async whiteboxUpload(req, res, next) {
    let extractedPath = null;

    try {
      // Validate file upload
      if (!req.file) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "No file uploaded. Please upload a ZIP file.",
        });
      }

      const { targetIp, targetPort, applicationName } = req.body;

      // Validate target IP
      if (!targetIp || !targetIp.trim()) {
        // Clean up uploaded file
        fs.unlinkSync(req.file.path);
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "Target IP is required",
        });
      }

      logger.info("Processing whitebox ZIP upload", {
        filename: req.file.originalname,
        size: req.file.size,
        targetIp,
        applicationName,
      });

      // Validate ZIP file
      if (!req.file.originalname.toLowerCase().endsWith(".zip")) {
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
        "payload-recon",
        `whitebox_${timestamp}`
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

      // Call Python backend to start whitebox scan
      const whiteboxResult = await pythonBridge.whiteboxWorkflow({
        source_path: extractedPath,
        target_ip: targetIp.trim(),
        target_port: targetPort || "80",
        application_name: applicationName || req.file.originalname.replace(".zip", ""),
      });

      if (!whiteboxResult.success) {
        throw new Error(whiteboxResult.error || "Whitebox workflow failed");
      }

      logger.info("Whitebox workflow initiated", {
        scan_id: whiteboxResult.data.scan_id,
      });

      return res.status(HTTP_STATUS.OK).json({
        success: true,
        message: "Whitebox scan initiated successfully",
        data: {
          scan_id: whiteboxResult.data.scan_id,
          status: whiteboxResult.data.status,
          redirect_to_scan: true,
        },
      });
    } catch (error) {
      logger.error("Error processing whitebox upload", { error: error.message });

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
}

export default new ReconController();
