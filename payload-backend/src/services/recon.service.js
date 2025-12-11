import { getDb } from "../utils/mongo-connector.js";
import { DB_CONFIG } from "../config/database.js";

/**
 * Service layer for recon-related business logic
 */
class ReconService {
  /**
   * Get paginated recon history
   * @param {Object} opts - { page, limit, sort }
   * @returns {Promise<Object>}
   */
  async getReconHistory({ page = 1, limit = 10, sort = -1 }) {
    const db = getDb();
    const reconCollection = db.collection(DB_CONFIG.COLLECTIONS.RECON);

    const safePage = Math.max(1, parseInt(page, 10) || 1);
    const safeLimit = Math.max(1, parseInt(limit, 10) || 10);
    const skip = (safePage - 1) * safeLimit;

    // projection - only fields we need
    const projection = {
      scan_name: 1,
      target_ip: 1,
      ip: 1,
      status: 1,
      scan_time: 1,
      completed_at: 1,
      timestamp: 1,
      scan_id: 1,
    };

    // Build cursor sorted by timestamp
    const cursor = reconCollection
      .find({}, { projection })
      .sort({ timestamp: sort })
      .skip(skip)
      .limit(safeLimit);

    const docs = await cursor.toArray();

    // total count for pagination
    const total = await reconCollection.countDocuments();

    // transform documents
    const recons = docs.map((doc) => {
      // determine ip field (target_ip preferred)
      const ip = doc.target_ip || doc.ip || null;

      // calculate execution time from scan_time and completed_at
      let exec_time = null;
      try {
        if (doc.scan_time && doc.completed_at) {
          const startedDate = new Date(doc.scan_time);
          const completedDate = new Date(doc.completed_at);
          if (
            !Number.isNaN(startedDate.getTime()) &&
            !Number.isNaN(completedDate.getTime())
          ) {
            const diffMs = completedDate.getTime() - startedDate.getTime();
            if (diffMs >= 0) {
              const totalSeconds = Math.floor(diffMs / 1000);
              const minutes = Math.floor(totalSeconds / 60);
              const seconds = totalSeconds % 60;
              if (minutes > 0) {
                exec_time = `${minutes}m ${seconds}s`;
              } else {
                exec_time = `${seconds}s`;
              }
            }
          }
        }
      } catch (e) {
        exec_time = null;
      }

      // date extracted from timestamp field (YYYY-MM-DD)
      let date = null;
      const ts = doc.timestamp || null;
      if (ts) {
        try {
          const dt = new Date(ts);
          if (!Number.isNaN(dt.getTime())) {
            date = dt.toISOString().split("T")[0];
          }
        } catch (e) {
          date = null;
        }
      }

      return {
        scan_id: doc.scan_id || null,
        scan_name: doc.scan_name || "Unknown",
        ip,
        status: doc.status || "unknown",
        exec_time, // seconds (float) or null
        date,
      };
    });

    const totalPages = Math.max(1, Math.ceil(total / safeLimit));

    return {
      success: true,
      page: safePage,
      limit: safeLimit,
      total,
      totalPages,
      recons,
    };
  }

  /**
   * Get a single recon by scan_id with all details
   * @param {string} scanId - The scan_id to look up
   * @returns {Promise<Object>}
   */
  async getReconById(scanId) {
    const db = getDb();
    const reconCollection = db.collection(DB_CONFIG.COLLECTIONS.RECON);

    const doc = await reconCollection.findOne({ scan_id: scanId });

    if (!doc) {
      return {
        success: false,
        message: "Recon not found",
      };
    }

    // Calculate execution time
    let exec_time = null;
    try {
      if (doc.scan_time && doc.completed_at) {
        const startedDate = new Date(doc.scan_time);
        const completedDate = new Date(doc.completed_at);
        if (
          !Number.isNaN(startedDate.getTime()) &&
          !Number.isNaN(completedDate.getTime())
        ) {
          const diffMs = completedDate.getTime() - startedDate.getTime();
          if (diffMs >= 0) {
            const totalSeconds = Math.floor(diffMs / 1000);
            const minutes = Math.floor(totalSeconds / 60);
            const seconds = totalSeconds % 60;
            if (minutes > 0) {
              exec_time = `${minutes}m ${seconds}s`;
            } else {
              exec_time = `${seconds}s`;
            }
          }
        }
      }
    } catch (e) {
      exec_time = null;
    }

    // Format date
    let date = null;
    if (doc.timestamp) {
      try {
        const dt = new Date(doc.timestamp);
        if (!Number.isNaN(dt.getTime())) {
          date = dt.toISOString().split("T")[0];
        }
      } catch (e) {
        date = null;
      }
    }

    return {
      success: true,
      recon: {
        scan_id: doc.scan_id,
        scan_name: doc.scan_name || "Unknown",
        target_ip: doc.target_ip || doc.ip || null,
        status: doc.status || "unknown",
        mode: doc.mode || null,
        exec_time,
        date,
        timestamp: doc.timestamp,
        scan_time: doc.scan_time,
        completed_at: doc.completed_at,
        os_info: doc.os_info || null,
        services: doc.services || [],
      },
    };
  }
}

export default new ReconService();
