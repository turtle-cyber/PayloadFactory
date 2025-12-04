import express from "express";
import scanRoutes from "./scan.routes.js";
import dashboardRoutes from "./dashboard.routes.js";
import findingsRoutes from "./findings.routes.js";
import downloadRoutes from "./download.routes.js";

const router = express.Router();

// Mount routes
router.use("/scans", scanRoutes);
router.use("/dashboard", dashboardRoutes);
router.use("/findings", findingsRoutes);
router.use("/download", downloadRoutes);

// Health check for API
router.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "API is healthy",
    timestamp: new Date().toISOString(),
  });
});

export default router;
