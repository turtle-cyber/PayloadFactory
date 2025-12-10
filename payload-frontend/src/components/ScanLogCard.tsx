import React, { useEffect, useRef, useState, useCallback } from "react";
import { http } from "../utils/http";

interface ScanLog {
  _id: string;
  scan_id: string;
  message: string;
  level: string;
  timestamp: string;
}

interface ScanLogCardProps {
  scanId?: string | null;
  isScanning?: boolean;
}

const ScanLogCard: React.FC<ScanLogCardProps> = ({ scanId, isScanning }) => {
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [totalLogs, setTotalLogs] = useState(0);
  const logContainerRef = useRef<HTMLDivElement>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastOffsetRef = useRef(0);

  const fetchLogs = useCallback(async () => {
    if (!scanId) {
      console.log("[ScanLogCard] No scanId yet");
      return;
    }

    console.log("[ScanLogCard] Fetching logs for scanId:", scanId);

    try {
      const response = await http.get(`/scans/${scanId}/logs`, {
        params: {
          offset: lastOffsetRef.current,
          limit: 100,
        },
      });

      console.log("[ScanLogCard] API Response:", response.data);

      if (response.data.success && response.data.data) {
        const newLogs = response.data.data.logs || [];
        const total = response.data.data.total || 0;

        if (newLogs.length > 0) {
          setLogs((prev) => [...prev, ...newLogs]);
          lastOffsetRef.current += newLogs.length;
        }
        setTotalLogs(total);
      }
    } catch (error) {
      console.error("[ScanLogCard] Error fetching scan logs:", error);
    }
  }, [scanId]);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  // Start/stop polling based on scanId and scanning state
  useEffect(() => {
    // Clear previous state when scanId changes
    if (scanId) {
      setLogs([]);
      lastOffsetRef.current = 0;
      setTotalLogs(0);

      // Fetch immediately
      fetchLogs();

      // Start polling
      pollingRef.current = setInterval(fetchLogs, 2000);
    }

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    };
  }, [scanId, fetchLogs]);

  // Stop polling when scan completes
  useEffect(() => {
    if (!isScanning && pollingRef.current) {
      // Do one final fetch to get remaining logs
      fetchLogs();
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, [isScanning, fetchLogs]);

  const getLogColor = (level: string) => {
    switch (level.toLowerCase()) {
      case "error":
        return "text-red-400";
      case "warning":
        return "text-yellow-400";
      case "debug":
        return "text-gray-500";
      default:
        return "text-green-400";
    }
  };

  const formatTimestamp = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString("en-US", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
    } catch {
      return "";
    }
  };

  return (
    <div>
      <div className="items-center flex gap-2 justify-between">
        <div className="flex items-center gap-2">
          <div className="text-gray-400">
            {/* <Signpost className="w-5" /> */}
          </div>
          <h2 className="text-blue-500 text-lg">Scan Logs</h2>
        </div>
        {totalLogs > 0 && (
          <span className="text-gray-500 text-sm">{totalLogs} entries</span>
        )}
      </div>

      {/* Terminal Window */}
      <div className="p-4">
        <div className="items-center justify-between flex rounded-t-lg bg-[#2f2f2f] py-2 px-4">
          <span className="font-md text-gray-500"></span>
          {isScanning && (
            <span className="flex items-center gap-2 text-green-400 text-sm">
              <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
              Live
            </span>
          )}
        </div>

        <div
          ref={logContainerRef}
          className="border-[#2f2f2f] border bg-[#0d0d0d] p-4 rounded-b-lg h-[40vh] overflow-auto font-mono text-sm"
        >
          {logs.length === 0 ? (
            <div className="text-gray-600 italic">
              {scanId
                ? "Waiting for logs..."
                : "Start a scan to see logs here"}
            </div>
          ) : (
            logs.map((log, index) => (
              <div key={log._id || index} className="py-0.5">
                <span className="text-gray-600">
                  [{formatTimestamp(log.timestamp)}]
                </span>{" "}
                <span className={getLogColor(log.level)}>{log.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanLogCard;
