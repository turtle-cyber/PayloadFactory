import { useState, useEffect, useRef } from "react";
import { http } from "../utils/http";
import { GET_AGENT_LOGS } from "../endpoints/agent.endpoints";

export interface AgentLog {
  timestamp: string;
  level: string;
  logger: string;
  message: string;
  module: string;
  line: number;
}

interface UseAgentLogsReturn {
  logs: AgentLog[];
  loading: boolean;
  error: string | null;
  clearLogs: () => void;
}

export function useAgentLogs(
  refreshInterval: number = 5000
): UseAgentLogsReturn {
  const [logs, setLogs] = useState<AgentLog[]>([]);
  const [offset, setOffset] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const isMounted = useRef<boolean>(true);

  const fetchLogs = async () => {
    if (!isMounted.current) return;

    try {
      setLoading(true);
      setError(null);

      const response = await http.get(GET_AGENT_LOGS, {
        params: {
          offset,
          limit: 100,
        },
      });

      if (response.status === 200 && response.data.success) {
        const { logs: newLogs, offset: newOffset } = response.data.data;

        if (newLogs.length > 0) {
          setLogs((prevLogs) => {
            // Append new logs to existing logs
            const updatedLogs = [...prevLogs, ...newLogs];

            // Keep only last 1000 logs for performance
            if (updatedLogs.length > 1000) {
              return updatedLogs.slice(-1000);
            }

            return updatedLogs;
          });

          setOffset(newOffset);
        }
      }
    } catch (err: any) {
      console.error("Error fetching agent logs:", err);
      setError(err.message || "Failed to fetch logs");
    } finally {
      setLoading(false);
    }
  };

  const clearLogs = () => {
    setLogs([]);
    setOffset(0);
  };

  useEffect(() => {
    isMounted.current = true;

    // Initial fetch
    fetchLogs();

    // Set up polling interval
    const interval = setInterval(() => {
      fetchLogs();
    }, refreshInterval);

    // Cleanup
    return () => {
      isMounted.current = false;
      clearInterval(interval);
    };
  }, [offset, refreshInterval]);

  return { logs, loading, error, clearLogs };
}
