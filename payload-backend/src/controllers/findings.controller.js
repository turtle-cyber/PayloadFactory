import findingsService from "../services/findings.service.js";
import { HTTP_STATUS } from "../config/constants.js";
import { logger } from "../utils/logger.js";

/**
 * Controller for findings-related endpoints
 */
class FindingsController {
  /**
   * Get findings by scan ID
   * @route GET /api/findings?scan_id=<scan_id>
   */
  async getFindingsByScanId(req, res, next) {
    try {
      const scanId = req.query.scan_id;

      if (!scanId) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          message: "scan_id is required",
        });
      }

      logger.info(`Fetching findings for scan ID: ${scanId}`);

      const result = await findingsService.getFindingsByScanId(scanId);

      logger.info(
        `Successfully fetched ${result.findings.length} findings for scan ID: ${scanId}`
      );

      return res.status(HTTP_STATUS.OK).json(result);
    } catch (error) {
      logger.error("Error fetching findings by scan ID", {
        error: error.message,
      });
      next(error);
    }
  }
}

export default new FindingsController();
