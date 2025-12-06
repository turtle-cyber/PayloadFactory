import { readFileSync, existsSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Service layer for agent log operations
 */
class AgentService {
  /**
   * Get path to scan_log.json in project root
   * @returns {string} Absolute path to log file
   */
  getLogFilePath() {
    // Go up from src/services to project root
    return join(__dirname, "../../../scan_log.json");
  }

  /**
   * Check if a log entry is an agent log
   * @param {Object} logEntry - Parsed log entry
   * @returns {boolean} True if it's an agent log
   */
  isAgentLog(logEntry) {
    return (
      logEntry.message &&
      logEntry.message.includes("Received agent log")
    );
  }

  /**
   * Get agent logs from file starting from offset
   * @param {number} offset - Byte position to start reading from
   * @param {number} limit - Maximum number of logs to return
   * @returns {Promise<Object>} Logs and new offset
   */
  async getLogsFromFile(offset = 0, limit = 100) {
    const logFilePath = this.getLogFilePath();

    // Check if file exists
    if (!existsSync(logFilePath)) {
      return {
        success: true,
        data: {
          logs: [],
          offset: 0,
          hasMore: false,
          fileSize: 0,
        },
      };
    }

    try {
      // Get file size
      const stats = statSync(logFilePath);
      const fileSize = stats.size;

      // If offset is beyond file size, reset it
      if (offset > fileSize) {
        offset = 0;
      }

      // Read file content from offset
      const fileContent = readFileSync(logFilePath, "utf8");
      const lines = fileContent.split("\n");

      // Track byte position and parse logs
      let currentBytePos = 0;
      const logs = [];
      let processedBytes = offset;

      for (const line of lines) {
        const lineBytes = Buffer.byteLength(line + "\n", "utf8");

        // Skip lines until we reach the offset
        if (currentBytePos < offset) {
          currentBytePos += lineBytes;
          continue;
        }

        // Stop if we've collected enough logs
        if (logs.length >= limit) {
          break;
        }

        // Try to parse JSON line
        if (line.trim()) {
          try {
            const logEntry = JSON.parse(line);

            // Only include agent logs
            if (this.isAgentLog(logEntry)) {
              logs.push(logEntry);
            }

            processedBytes += lineBytes;
          } catch (e) {
            // Skip malformed JSON lines
            processedBytes += lineBytes;
          }
        } else {
          processedBytes += lineBytes;
        }

        currentBytePos += lineBytes;
      }

      return {
        success: true,
        data: {
          logs,
          offset: processedBytes,
          hasMore: processedBytes < fileSize,
          fileSize,
        },
      };
    } catch (error) {
      throw new Error(`Failed to read log file: ${error.message}`);
    }
  }

  /**
   * Get recent agent logs (helper method)
   * @param {number} limit - Maximum number of logs to return
   * @returns {Promise<Object>} Recent logs
   */
  async getRecentLogs(limit = 100) {
    const logFilePath = this.getLogFilePath();

    if (!existsSync(logFilePath)) {
      return {
        success: true,
        data: {
          logs: [],
        },
      };
    }

    try {
      const fileContent = readFileSync(logFilePath, "utf8");
      const lines = fileContent.split("\n").filter((line) => line.trim());

      const logs = [];

      // Parse from end of file backwards
      for (let i = lines.length - 1; i >= 0 && logs.length < limit; i--) {
        try {
          const logEntry = JSON.parse(lines[i]);

          // Only include agent logs
          if (this.isAgentLog(logEntry)) {
            logs.unshift(logEntry);
          }
        } catch (e) {
          // Skip malformed JSON
        }
      }

      return {
        success: true,
        data: {
          logs,
        },
      };
    } catch (error) {
      throw new Error(`Failed to read log file: ${error.message}`);
    }
  }
}

export default new AgentService();
