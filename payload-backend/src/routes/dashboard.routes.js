import express from "express";
import dashboardController from "../controllers/dashboard.controller.js";

const router = express.Router();

// Platform Metrics
router.get("/metrics", dashboardController.getPlatformMetrics);

// Analytics Routes
router.get(
  "/analytics/repos-by-severity",
  dashboardController.getReposBySeverity
);
router.get(
  "/analytics/severity-heatmap",
  dashboardController.getSeverityHeatmap
);
router.get(
  "/analytics/exploits-by-type",
  dashboardController.getExploitsByType
);
router.get(
  "/analytics/exploits-by-owasp",
  dashboardController.getExploitsByOwasp
);
router.get("/analytics", dashboardController.getAllAnalytics);

// Exploit Routes
router.get("/exploits/stats", dashboardController.getExploitStatistics);
router.get("/exploits/scan/:scanId", dashboardController.getExploitsByScanId);
router.get("/exploits/:exploitId", dashboardController.getExploitById);
router.get("/exploits", dashboardController.getAllExploits);

export default router;
