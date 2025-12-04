import agentService from "../services/agent.service.js";
import { logger } from "../utils/logger.js";

/**
 * Controller for agent log endpoints
 */
class AgentController {
  /**
   * Get agent logs from scan_log.json
   * @route GET /api/agent/logs?offset=0&limit=100
   */
  async getAgentLogs(req, res, next) {
    try {
      const offset = parseInt(req.query.offset) || 0;
      const limit = parseInt(req.query.limit) || 100;

      logger.info("Fetching agent logs", { offset, limit });

      const result = await agentService.getLogsFromFile(offset, limit);
      res.json(result);
    } catch (error) {
      logger.error("Error fetching agent logs", { error: error.message });
      next(error);
    }
  }

  /**
   * Get recent agent logs
   * @route GET /api/agent/logs/recent?limit=100
   */
  async getRecentLogs(req, res, next) {
    try {
      const limit = parseInt(req.query.limit) || 100;

      logger.info("Fetching recent agent logs", { limit });

      const result = await agentService.getRecentLogs(limit);
      res.json(result);
    } catch (error) {
      logger.error("Error fetching recent agent logs", {
        error: error.message,
      });
      next(error);
    }
  }
}

export default new AgentController();
