import express from "express";
import multer from "multer";
import path from "path";
import os from "os";
import fs from "fs";
import reconController from "../controllers/recon.controller.js";

const router = express.Router();

// Configure multer for file uploads
const uploadDir = path.join(os.tmpdir(), "payload-recon-uploads");

// Ensure upload directory exists
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB max file size
  },
  fileFilter: (req, file, cb) => {
    // Accept only ZIP files
    if (file.mimetype === "application/zip" ||
        file.mimetype === "application/x-zip-compressed" ||
        file.originalname.toLowerCase().endsWith(".zip")) {
      cb(null, true);
    } else {
      cb(new Error("Only ZIP files are allowed"));
    }
  },
});

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
 * @route   POST /api/recon/simulation-setup
 * @desc    Generate simulation/lab setup guide for a selected service
 * @access  Public
 * @body    { service, os_info? }
 */
router.post("/simulation-setup", reconController.simulationSetup.bind(reconController));

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

/**
 * @route   POST /api/recon/whitebox/upload
 * @desc    Upload ZIP and initiate whitebox exploitation workflow
 * @access  Public
 * @body    FormData with zipFile, targetIp, targetPort?, applicationName?
 */
router.post("/whitebox/upload", upload.single("zipFile"), reconController.whiteboxUpload.bind(reconController));

export default router;
