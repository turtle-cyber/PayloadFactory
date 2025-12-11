import { HTTP_STATUS } from "../config/constants.js";
import { logger } from "../utils/logger.js";
import pythonBridge from "../services/python-bridge.service.js";
import fs from "fs";
import path from "path";
import os from "os";
import AdmZip from "adm-zip";
import reconService from "../services/recon.service.js";

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
        ports: ports && ports.trim() ? ports.trim() : undefined,
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
          os_info: scanResult.data.os_info,
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
   * Generate simulation/lab setup guide for a service
   * @route POST /api/recon/simulation-setup
   */
  async simulationSetup(req, res, next) {
    try {
      const { service, os_info } = req.body;

      // Validate input
      if (!service || !service.port) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "Service information is required",
        });
      }

      logger.info("Generating simulation setup", {
        port: service.port,
        product: service.product || service.service,
      });

      // Call Python backend for simulation setup
      const axios = (await import("axios")).default;
      const response = await axios.post(
        `${
          process.env.PYTHON_API_URL || "http://localhost:8000"
        }/recon/simulation-setup`,
        {
          service: service,
          os_info: os_info || null,
        },
        { timeout: 120000 } // 2 minute timeout for LLM generation
      );

      if (!response.data.success) {
        return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
          success: false,
          message: "Failed to generate simulation setup",
        });
      }

      logger.info("Simulation setup generated successfully", {
        port: service.port,
      });

      return res.status(HTTP_STATUS.OK).json({
        success: true,
        message: "Simulation setup generated successfully",
        data: {
          setup_data: response.data.setup_data,
          formatted_guide: response.data.formatted_guide,
        },
      });
    } catch (error) {
      logger.error("Error generating simulation setup", {
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
        ports: ports && ports.trim() ? ports.trim() : undefined,
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

      const {
        targetIp,
        targetPort,
        applicationName,
        attackMode,
        autoExec,
        demoMode,
      } = req.body;

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
        attackMode: attackMode === "true",
        autoExec: autoExec === "true",
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
      // Whitebox mode enables attack mode and auto-execution by default
      const whiteboxResult = await pythonBridge.whiteboxWorkflow({
        source_path: extractedPath,
        target_ip: targetIp.trim(),
        target_port: targetPort || "8080",
        application_name:
          applicationName || req.file.originalname.replace(".zip", ""),
        attack_mode: attackMode === "true",
        auto_execute: autoExec === "true",
        demo_mode: demoMode === "true",
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
      logger.error("Error processing whitebox upload", {
        error: error.message,
      });

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

  async getReconHistory(req, res, next) {
    try {
      const page = parseInt(req.query.page, 10) || 1;
      const limit = parseInt(req.query.limit, 10) || 10;
      const sortParam = (req.query.sort || "desc").toLowerCase();
      const sort = sortParam === "asc" ? 1 : -1;

      logger.info("Fetching recon history", { page, limit, sort: sortParam });

      const result = await reconService.getReconHistory({ page, limit, sort });

      logger.info("Recon history fetched", {
        returned: result.recons.length,
        page: result.page,
        total: result.total,
      });

      return res.status(HTTP_STATUS.OK).json(result);
    } catch (error) {
      logger.error("Error fetching recon history", { error: error.message });
      next(error);
    }
  }

  /**
   * Get a single recon by scan_id
   * @route GET /api/recon/history?id=scan_id
   */
  async getReconById(req, res, next) {
    try {
      const { id } = req.query;

      if (!id) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "Recon ID is required",
        });
      }

      logger.info("Fetching recon by ID", { scan_id: id });

      const result = await reconService.getReconById(id);

      if (!result.success) {
        return res.status(HTTP_STATUS.NOT_FOUND).json(result);
      }

      logger.info("Recon fetched", { scan_id: id });

      return res.status(HTTP_STATUS.OK).json(result);
    } catch (error) {
      logger.error("Error fetching recon by ID", { error: error.message });
      next(error);
    }
  }
}

export default new ReconController();
