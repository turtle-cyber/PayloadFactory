import express from "express";
import agentController from "../controllers/agent.controller.js";

const router = express.Router();

// Get agent logs with offset-based pagination
router.get("/logs", agentController.getAgentLogs);

// Get recent agent logs
router.get("/logs/recent", agentController.getRecentLogs);

export default router;
