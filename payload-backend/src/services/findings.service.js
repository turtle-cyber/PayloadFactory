import { getDb } from "../utils/mongo-connector.js";
import { DB_CONFIG } from "../config/database.js";
import { existsSync } from "fs";
import { resolve } from "path";
import analyticsService from "./analytics.service.js";

/**
 * Service layer for findings-related business logic
 */
class FindingsService {
  /**
   * Get all findings for a specific scan
   * Filters out findings where cwe_id is "Unknown" or "Safe"
   * @param {string} scanId - The scan ID
   * @returns {Promise<Object>} Findings data with severity counts
   */
  async getFindingsByScanId(scanId) {
    const db = getDb();
    const findingsCollection = db.collection(DB_CONFIG.COLLECTIONS.FINDINGS);

    // Fetch all findings for this scan, excluding Unknown, Safe, null, or missing CWEs
    const findings = await findingsCollection
      .find({
        scan_id: scanId,
        cwe_id: {
          $exists: true,
          $nin: ["Unknown", "Safe", null, ""],
        },
      })
      .toArray();

    // Calculate severity counts
    const severityCounts = {
      total: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };

    // Transform findings and count by severity
    const transformedFindings = findings.map((finding) => {
      // Use unified severity classification (matches Python backend)
      const confidence = finding.details?.confidence || 0;
      const cvss_score = finding.details?.cvss_score || null;
      const keywords = finding.details?.keywords || [];
      const cve_count = finding.details?.cve_count || 0;

      const severity = analyticsService.getSeverityLevel({
        confidence,
        cvss_score,
        keywords,
        cve_count
      });

      // Count by severity
      const severityLower = severity.toLowerCase();
      if (severityCounts[severityLower] !== undefined) {
        severityCounts[severityLower]++;
      } else {
        severityCounts.unknown++;
      }

      // Extract exploit path (first exploit's path if exists)
      const exploitPath =
        finding.exploits && finding.exploits.length > 0
          ? finding.exploits[0].path
          : null;

      return {
        severity,
        cwe: finding.cwe_id || "Unknown",
        cve: finding.details.cve || "Unknown",
        file: finding.file_name || "Unknown",
        file_path: finding.file_path || "Unknown",
        line: finding.line_number || 0,
        confidence: parseFloat(confidence.toFixed(3)),
        exploit_path: exploitPath,
      };
    });

    return {
      success: true,
      scan_id: scanId,
      counts: severityCounts,
      findings: transformedFindings,
    };
  }

  /**
   * Get exploit file path for download
   * @param {string} exploitPath - The exploit file path from database
   * @returns {Promise<Object>} File path info
   */
  async getExploitFilePath(exploitPath) {
    if (!exploitPath) {
      return {
        success: false,
        message: "Exploit path not provided",
      };
    }

    // Resolve the full path
    const fullPath = resolve(exploitPath);

    // Check if file exists
    if (!existsSync(fullPath)) {
      return {
        success: false,
        message: "Exploit file not found on server",
      };
    }

    return {
      success: true,
      filePath: fullPath,
    };
  }
}

export default new FindingsService();
