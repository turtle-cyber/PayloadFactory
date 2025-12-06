import express from "express";
import reconController from "../controllers/recon.controller.js";

const router = express.Router();

/**
 * @route   POST /api/recon/scan
 * @desc    Scan network target for open ports and services
 * @access  Public
 * @body    { target_ip, ports?, application_name? }
 */
router.post("/scan", reconController.scanNetwork.bind(reconController));

/**
 * @route   POST /api/recon/analyze
 * @desc    Analyze discovered services using LLM
 * @access  Public
 * @body    { services[], model? }
 */
router.post("/analyze", reconController.analyzeServices.bind(reconController));

/**
 * @route   POST /api/recon/blackbox
 * @desc    Run blackbox exploitation analysis (CVE matching, exploit lookup, fuzzing)
 * @access  Public
 * @body    { target_ip, ports?, services? }
 */
router.post("/blackbox", reconController.blackboxAnalysis.bind(reconController));

/**
 * @route   POST /api/recon/whitebox
 * @desc    Initiate whitebox exploitation workflow
 * @access  Public
 * @body    { source_path, target_ip, target_port?, application_name? }
 */
router.post("/whitebox", reconController.whiteboxWorkflow.bind(reconController));

export default router;
