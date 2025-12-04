import dashboardService from "../services/dashboard.service.js";
import analyticsService from "../services/analytics.service.js";
import exploitsService from "../services/exploits.service.js";
import { logger } from "../utils/logger.js";

/**
 * Controller for dashboard-related endpoints
 */
class DashboardController {
  /**
   * Get platform metrics
   * @route GET /api/dashboard/metrics
   */
  async getPlatformMetrics(req, res, next) {
    try {
      logger.info("Fetching platform metrics");
      const result = await dashboardService.getPlatformMetrics();
      res.json(result);
    } catch (error) {
      logger.error("Error fetching platform metrics", { error: error.message });
      next(error);
    }
  }

  /**
   * Get repos by severity
   * @route GET /api/dashboard/analytics/repos-by-severity
   */
  async getReposBySeverity(req, res, next) {
    try {
      logger.info("Fetching repos by severity");
      const result = await analyticsService.getReposBySeverity();
      res.json(result);
    } catch (error) {
      logger.error("Error fetching repos by severity", {
        error: error.message,
      });
      next(error);
    }
  }

  /**
   * Get severity heatmap
   * @route GET /api/dashboard/analytics/severity-heatmap
   */
  async getSeverityHeatmap(req, res, next) {
    try {
      logger.info("Fetching severity heatmap");
      const result = await analyticsService.getSeverityHeatmap();
      res.json(result);
    } catch (error) {
      logger.error("Error fetching severity heatmap", {
        error: error.message,
      });
      next(error);
    }
  }

  /**
   * Get exploits by type
   * @route GET /api/dashboard/analytics/exploits-by-type
   */
  async getExploitsByType(req, res, next) {
    try {
      logger.info("Fetching exploits by type");
      const result = await analyticsService.getExploitsByType();
      res.json(result);
    } catch (error) {
      logger.error("Error fetching exploits by type", { error: error.message });
      next(error);
    }
  }

  /**
   * Get exploits by OWASP category
   * @route GET /api/dashboard/analytics/exploits-by-owasp
   */
  async getExploitsByOwasp(req, res, next) {
    try {
      logger.info("Fetching exploits by OWASP");
      const result = await analyticsService.getExploitsByOwasp();
      res.json(result);
    } catch (error) {
      logger.error("Error fetching exploits by OWASP", {
        error: error.message,
      });
      next(error);
    }
  }

  /**
   * Get all analytics data
   * @route GET /api/dashboard/analytics
   */
  async getAllAnalytics(req, res, next) {
    try {
      logger.info("Fetching all analytics");
      const result = await analyticsService.getAllAnalytics();
      res.json(result);
    } catch (error) {
      logger.error("Error fetching all analytics", { error: error.message });
      next(error);
    }
  }

  /**
   * Get all exploits with pagination
   * @route GET /api/dashboard/exploits
   */
  async getAllExploits(req, res, next) {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;

      logger.info("Fetching all exploits", { page, limit });
      const result = await exploitsService.getAllExploits(page, limit);
      res.json(result);
    } catch (error) {
      logger.error("Error fetching all exploits", { error: error.message });
      next(error);
    }
  }

  /**
   * Get exploits by scan ID
   * @route GET /api/dashboard/exploits/scan/:scanId
   */
  async getExploitsByScanId(req, res, next) {
    try {
      const { scanId } = req.params;

      logger.info("Fetching exploits by scan ID", { scanId });
      const result = await exploitsService.getExploitsByScanId(scanId);
      res.json(result);
    } catch (error) {
      logger.error("Error fetching exploits by scan ID", {
        error: error.message,
      });
      next(error);
    }
  }

  /**
   * Get exploit by ID
   * @route GET /api/dashboard/exploits/:exploitId
   */
  async getExploitById(req, res, next) {
    try {
      const { exploitId } = req.params;

      logger.info("Fetching exploit by ID", { exploitId });
      const result = await exploitsService.getExploitById(exploitId);

      if (!result.success) {
        return res.status(404).json(result);
      }

      res.json(result);
    } catch (error) {
      logger.error("Error fetching exploit by ID", { error: error.message });
      next(error);
    }
  }

  /**
   * Get exploit statistics
   * @route GET /api/dashboard/exploits/stats
   */
  async getExploitStatistics(req, res, next) {
    try {
      logger.info("Fetching exploit statistics");
      const result = await exploitsService.getExploitStatistics();
      res.json(result);
    } catch (error) {
      logger.error("Error fetching exploit statistics", {
        error: error.message,
      });
      next(error);
    }
  }
}

export default new DashboardController();
