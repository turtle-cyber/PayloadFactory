import { getDb } from "../utils/mongo-connector.js";
import { DB_CONFIG } from "../config/database.js";

/**
 * Service layer for dashboard platform metrics
 */
class DashboardService {
  /**
   * Get platform metrics for dashboard
   * @returns {Promise<Object>} Platform metrics
   */
  async getPlatformMetrics() {
    const db = getDb();
    const scansCollection = db.collection(DB_CONFIG.COLLECTIONS.SCANS);
    const findingsCollection = db.collection(DB_CONFIG.COLLECTIONS.FINDINGS);

    // Get total repos uploaded (total scans)
    const totalRepos = await scansCollection.countDocuments();

    // Get total exploits generated (count exploits array elements in findings)
    const exploitCountResult = await findingsCollection
      .aggregate([
        {
          $project: {
            exploitCount: { $size: { $ifNull: ["$exploits", []] } },
          },
        },
        {
          $group: {
            _id: null,
            total: { $sum: "$exploitCount" },
          },
        },
      ])
      .toArray();

    const totalExploits =
      exploitCountResult.length > 0 ? exploitCountResult[0].total : 0;

    // Get active scans (status: "processing")
    const activeScans = await scansCollection.countDocuments({
      status: "processing",
    });

    // Get pending vulnerabilities (findings without classification)
    const pendingVulnerabilities = await findingsCollection.countDocuments({
      "details.classification": null,
    });

    return {
      success: true,
      data: {
        totalRepos,
        totalExploits,
        activeScans,
        pendingVulnerabilities,
      },
    };
  }
}

export default new DashboardService();
