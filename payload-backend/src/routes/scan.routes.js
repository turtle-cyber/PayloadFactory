import express from "express";
import multer from "multer";
import scanController from "../controllers/scan.controller.js";
import path from "path";
import os from "os";
import fs from "fs";

const router = express.Router();

// Configure multer for file uploads
const uploadDir = path.join(os.tmpdir(), "payload-uploads");

// Ensure upload directory exists
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate unique filename
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
 * @route   GET /api/scans
 * @desc    Get all scans
 * @access  Public
 */
router.get("/", scanController.getAllScans.bind(scanController));

/**
 * @route   GET /api/scans/:id
 * @desc    Get a single scan by ID
 * @access  Public
 */
router.get("/:id", scanController.getScanById.bind(scanController));

/**
 * @route   POST /api/scans/upload
 * @desc    Upload ZIP file and start scan
 * @access  Public
 */
router.post("/upload", upload.single("zipFile"), scanController.uploadAndScan.bind(scanController));

/**
 * @route   GET /api/scans/:id/status
 * @desc    Get scan status and progress
 * @access  Public
 */
router.get("/:id/status", scanController.getScanStatus.bind(scanController));

/**
 * @route   POST /api/scans/:id/stop
 * @desc    Stop a running scan
 * @access  Public
 */
router.post("/:id/stop", scanController.stopScan.bind(scanController));

export default router;
