import { getDb } from "../utils/mongo-connector.js";
import { DB_CONFIG } from "../config/database.js";

/**
 * Service layer for scan-related business logic
 */
class ScanService {
  /**
   * Get all scans with formatted response
   * @returns {Promise<Object>} Formatted scan data
   */
  async getAllScans() {
    const db = getDb();
    const scansCollection = db.collection(DB_CONFIG.COLLECTIONS.SCANS);

    // Get total count of scans
    const scanCount = await scansCollection.countDocuments();

    // Fetch all scans
    const scans = await scansCollection.find({}).toArray();

    // Transform the data to match the required response format
    const hits = scans.map((scan) => {
      // Calculate execution time if both timestamps exist
      let executionTime = null;
      if (scan.timestamps?.submitted_at && scan.timestamps?.completed_at) {
        const submitted = new Date(scan.timestamps.submitted_at);
        const completed = new Date(scan.timestamps.completed_at);
        executionTime = Math.floor((completed - submitted) / 1000); // in seconds
      }

      return {
        id: scan._id || null,
        project_name: scan.project_name || null,
        file_size: scan.file_size || 0,
        root_path: scan.root_path || null,
        scan_status: scan.status || null,
        submitted_at: scan.timestamps?.submitted_at || null,
        date: scan.date || null,
        execution_time: executionTime,
      };
    });

    return {
      success: true,
      "scan-count": scanCount,
      hits,
    };
  }

  /**
   * Get a single scan by ID
   * @param {string} scanId - The scan ID
   * @returns {Promise<Object>} Scan data
   */
  async getScanById(scanId) {
    const db = getDb();
    const scansCollection = db.collection(DB_CONFIG.COLLECTIONS.SCANS);

    const scan = await scansCollection.findOne({ _id: new ObjectId(scanId) });

    if (!scan) {
      return null;
    }

    // Calculate execution time if both timestamps exist
    let executionTime = null;
    if (scan.timestamps?.submitted_at && scan.timestamps?.completed_at) {
      const submitted = new Date(scan.timestamps.submitted_at);
      const completed = new Date(scan.timestamps.completed_at);
      executionTime = Math.floor((completed - submitted) / 1000);
    }

    return {
      success: true,
      data: {
        project_name: scan.project_name || null,
        file_size: scan.file_size || 0,
        submitted_at: scan.timestamps?.submitted_at || null,
        date: scan.date || null,
        execution_time: executionTime,
        status: scan.status || null,
        stats: scan.stats || null,
      },
    };
  }
}

export default new ScanService();
