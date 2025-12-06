import { getDb } from "../utils/mongo-connector.js";
import { DB_CONFIG } from "../config/database.js";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load OWASP mapping from JSON file
const owaspMappingPath = join(__dirname, "../config/owasp-mapping.json");
const OWASP_MAPPING = JSON.parse(readFileSync(owaspMappingPath, "utf8"));

/**
 * Service layer for analytics and data aggregations
 */
class AnalyticsService {
  /**
   * Get severity classification based on confidence score
   * @param {number} confidence - Confidence score (0-1)
   * @returns {string} Severity level
   */
  getSeverityLevel(confidence) {
    if (confidence >= 0.8) return "HIGH";
    if (confidence >= 0.5) return "MEDIUM";
    return "LOW";
  }

  /**
   * Get repos grouped by severity level
   * @returns {Promise<Object>} Repos by severity data
   */
  async getReposBySeverity() {
    const db = getDb();
    const findingsCollection = db.collection(DB_CONFIG.COLLECTIONS.FINDINGS);

    // Aggregate findings by scan_id and calculate average confidence
    const results = await findingsCollection
      .aggregate([
        {
          $group: {
            _id: "$scan_id",
            avgConfidence: { $avg: "$details.confidence" },
            totalFindings: { $sum: 1 },
          },
        },
        {
          $bucket: {
            groupBy: "$avgConfidence",
            boundaries: [0, 0.5, 0.8, 1],
            default: "unknown",
            output: {
              count: { $sum: 1 },
            },
          },
        },
      ])
      .toArray();

    // Transform results into severity labels
    const severityMap = {
      0: "low",
      0.5: "medium",
      0.8: "high",
    };

    const data = {
      high: 0,
      medium: 0,
      low: 0,
    };

    results.forEach((result) => {
      const severityKey = severityMap[result._id];
      if (severityKey) {
        data[severityKey] = result.count;
      }
    });

    return {
      success: true,
      data,
    };
  }

  /**
   * Get severity heatmap data by date and day of week based on scans
   * @returns {Promise<Object>} Heatmap data
   */
  async getSeverityHeatmap() {
    const db = getDb();
    const scansCollection = db.collection(DB_CONFIG.COLLECTIONS.SCANS);

    // Get last 4 weeks of data
    const fourWeeksAgo = new Date();
    fourWeeksAgo.setDate(fourWeeksAgo.getDate() - 28);

    const results = await scansCollection
      .aggregate([
        {
          $match: {
            "timestamps.submitted_at": { $gte: fourWeeksAgo },
          },
        },
        {
          $project: {
            date: {
              $dateToString: {
                format: "%Y-%m-%d",
                date: "$timestamps.submitted_at"
              },
            },
            dayOfWeek: { $dayOfWeek: "$timestamps.submitted_at" },
            week: { $week: "$timestamps.submitted_at" },
            project_name: 1,
            vulnerabilities: { $ifNull: ["$stats.total_vulns", 0] },
            exploits: { $ifNull: ["$stats.total_exploits", 0] },
          },
        },
        {
          $group: {
            _id: {
              date: "$date",
              dayOfWeek: "$dayOfWeek",
              week: "$week",
            },
            scanCount: { $sum: 1 },
            totalExploits: { $sum: "$exploits" },
            avgVulnerabilities: { $avg: "$vulnerabilities" },
            // Collect scan details (project name and exploit count)
            scans: {
              $push: {
                name: "$project_name",
                exploits: "$exploits"
              }
            }
          },
        },
        {
          $sort: { "_id.date": 1 },
        },
        {
          $project: {
            _id: 0,
            date: "$_id.date",
            dayOfWeek: "$_id.dayOfWeek",
            week: "$_id.week",
            scanCount: 1,
            exploitCount: "$totalExploits",
            scans: 1,
            // Intensity based on average vulnerabilities (normalized 0-1)
            intensity: {
              $min: [
                1,
                { $divide: ["$avgVulnerabilities", 100] }
              ]
            },
          },
        },
      ])
      .toArray();

    return {
      success: true,
      data: results,
    };
  }

  /**
   * Get exploits grouped by CWE type
   * @returns {Promise<Object>} Exploits by type data
   */
  async getExploitsByType() {
    const db = getDb();
    const findingsCollection = db.collection(DB_CONFIG.COLLECTIONS.FINDINGS);

    const results = await findingsCollection
      .aggregate([
        {
          $unwind: "$exploits",
        },
        {
          $project: {
            // Extract only CWE code (e.g., "CWE-502" from "CWE-502: Deserialization of Untrusted Data")
            cweCode: {
              $arrayElemAt: [
                { $split: ["$exploits.cwe", ":"] },
                0
              ]
            }
          },
        },
        {
          $group: {
            _id: "$cweCode",
            count: { $sum: 1 },
          },
        },
        {
          $sort: { count: -1 },
        },
        {
          $project: {
            _id: 0,
            cwe: "$_id",
            count: 1,
          },
        },
      ])
      .toArray();

    return {
      success: true,
      data: results,
    };
  }

  /**
   * Get exploits grouped by OWASP category
   * @returns {Promise<Object>} Exploits by OWASP data
   */
  async getExploitsByOwasp() {
    const db = getDb();
    const findingsCollection = db.collection(DB_CONFIG.COLLECTIONS.FINDINGS);

    // Get all exploits from findings
    const findings = await findingsCollection
      .aggregate([
        {
          $unwind: "$exploits",
        },
        {
          $project: {
            cwe: "$exploits.cwe",
          },
        },
      ])
      .toArray();

    // Initialize OWASP categories from the mapping file
    const owaspCategories = {};
    OWASP_MAPPING.categories.forEach((category) => {
      owaspCategories[category] = 0;
    });

    // Map CWE to OWASP and count
    findings.forEach((finding) => {
      const cwe = finding.cwe;
      // Extract CWE number from string like "CWE-252: Source Code Execution"
      const cweMatch = cwe.match(/CWE-\d+/);
      if (cweMatch) {
        const cweCode = cweMatch[0];
        const owaspCategory = OWASP_MAPPING.cweToOwasp[cweCode];
        if (owaspCategory && owaspCategories[owaspCategory] !== undefined) {
          owaspCategories[owaspCategory]++;
        }
      }
    });

    // Filter out categories with count 0
    const filteredCategories = {};
    Object.entries(owaspCategories).forEach(([category, count]) => {
      if (count > 0) {
        filteredCategories[category] = count;
      }
    });

    return {
      success: true,
      data: filteredCategories,
    };
  }

  /**
   * Get all analytics data in a single call
   * @returns {Promise<Object>} All analytics data
   */
  async getAllAnalytics() {
    const [reposBySeverity, severityHeatmap, exploitsByType, exploitsByOwasp] =
      await Promise.all([
        this.getReposBySeverity(),
        this.getSeverityHeatmap(),
        this.getExploitsByType(),
        this.getExploitsByOwasp(),
      ]);

    return {
      success: true,
      data: {
        reposBySeverity: reposBySeverity.data,
        severityHeatmap: severityHeatmap.data,
        exploitsByType: exploitsByType.data,
        exploitsByOwasp: exploitsByOwasp.data,
      },
    };
  }
}

export default new AnalyticsService();
