import express from "express";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { logger } from "../utils/logger.js";

const router = express.Router();

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * GET /api/download
 * Download exploit files from the exploits directory
 *
 * Query params:
 *   - file_path: relative path to the file (e.g., "exploits/exploit_file.py")
 */
router.get("/", async (req, res, next) => {
  try {
    const { file_path } = req.query;

    if (!file_path) {
      return res.status(400).json({
        success: false,
        message: "Missing required parameter: file_path",
      });
    }

    // Get the project root (navigate up from routes -> src -> payload-backend -> project root)
    const projectRoot = path.resolve(__dirname, "../../..");

    // Normalize the file path to handle both forward and backward slashes
    const normalizedPath = file_path.replace(/\\/g, "/");

    // Construct the full file path
    const fullPath = path.resolve(projectRoot, normalizedPath);

    // Security check: ensure the file is within the project directory
    if (!fullPath.startsWith(projectRoot)) {
      logger.warn(`Path traversal attempt detected: ${file_path}`);
      return res.status(403).json({
        success: false,
        message: "Access denied: Invalid file path",
      });
    }

    // Check if file exists
    if (!fs.existsSync(fullPath)) {
      logger.warn(`File not found: ${fullPath}`);
      return res.status(404).json({
        success: false,
        message: `File not found: ${file_path}`,
      });
    }

    // Check if it's a file (not a directory)
    const stats = fs.statSync(fullPath);
    if (!stats.isFile()) {
      return res.status(400).json({
        success: false,
        message: "Path is not a file",
      });
    }

    // Get the filename for the download
    const filename = path.basename(fullPath);

    logger.info(`Downloading file: ${fullPath}`);

    // Set headers for file download
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Type", "application/octet-stream");

    // Stream the file to the client
    const fileStream = fs.createReadStream(fullPath);
    fileStream.pipe(res);

    fileStream.on("error", (error) => {
      logger.error("Error streaming file", { error: error.message });
      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          message: "Error downloading file",
        });
      }
    });
  } catch (error) {
    logger.error("Download error", { error: error.message, stack: error.stack });
    next(error);
  }
});

export default router;
