import express from "express";
import findingsController from "../controllers/findings.controller.js";

const router = express.Router();

/**
 * @route   GET /api/findings?scan_id=<scan_id>
 * @desc    Get findings by scan ID
 * @access  Public
 * @query   ?scan_id=<scan_id> - Required: filter by scan ID
 */
router.get("/", findingsController.getFindingsByScanId.bind(findingsController));

export default router;
