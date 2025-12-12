import { useRef, useEffect, useState } from "react";
import { useAgentLogs } from "../hooks/useAgentLogs";

const AgentPage = () => {
  const { logs, loading, error, clearLogs } = useAgentLogs(5000);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const logContainerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  // Get color based on log level
  const getLevelColor = (level: string): string => {
    switch (level.toUpperCase()) {
      case "ERROR":
        return "text-red-400";
      case "WARNING":
        return "text-yellow-400";
      case "CRITICAL":
        return "text-red-600";
      case "INFO":
        return "text-blue-400";
      default:
        return "text-gray-400";
    }
  };

  // Format timestamp for display
  const formatTimestamp = (timestamp: string): string => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString();
    } catch {
      return timestamp;
    }
  };

  return (
    <div className="text-white px-8 pb-6">
      <div className="px-24 mx-auto space-y-6">
        {/* Header Card - Command Instructions */}
        <div className="glassmorphism-card p-6 rounded-lg border border-red-500/20">
          <h2 className="text-xl font-semibold text-white mb-4">
            Run the following command on your Linux based target machine
          </h2>
          <div className="bg-black/50 px-4 py-3 rounded font-mono text-sm">
            <code className="text-green-400">
              python3 linux_agent.py --server http://YOUR_IP:8000
            </code>
          </div>
          <p className="text-gray-400 text-sm mt-3">
            Replace YOUR_IP with your machine's IP address. The agent will send
            logs to this server.
          </p>
        </div>

        {/* Logs Container */}
        <div className="glassmorphism-card p-6 rounded-lg border border-red-500/20">
          {/* Header */}
          <div className="flex justify-between items-center mb-4">
            <div className="flex items-center gap-4">
              <h3 className="text-lg font-semibold">Agent Logs</h3>
              {loading && (
                <span className="text-sm text-gray-400 animate-pulse">
                  Loading...
                </span>
              )}
              {logs.length > 0 && (
                <span className="text-sm text-gray-400">
                  {logs.length} log{logs.length !== 1 ? "s" : ""}
                </span>
              )}
            </div>

            <div className="flex gap-3 items-center">
              {/* Auto-scroll Toggle */}
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={(e) => setAutoScroll(e.target.checked)}
                  className="w-4 h-4 cursor-pointer"
                />
                <span className="text-sm text-gray-300">Auto-scroll</span>
              </label>

              {/* Clear Button */}
              <button
                onClick={clearLogs}
                className="px-3 py-1 text-sm bg-red-500/20 hover:bg-red-500/30 border border-red-500/50 rounded transition-colors"
              >
                Clear
              </button>
            </div>
          </div>

          {/* Error Display */}
          {error && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/50 rounded text-red-400 text-sm">
              Error: {error}
            </div>
          )}

          {/* Scrollable Logs */}
          <div
            ref={logContainerRef}
            className="bg-black/50 rounded p-4 h-[600px] overflow-y-auto font-mono text-sm"
            style={{
              scrollBehavior: autoScroll ? "smooth" : "auto",
            }}
          >
            {logs.length === 0 ? (
              <div className="flex items-center justify-center h-full text-gray-500">
                No agent logs yet. Waiting for agents to connect...
              </div>
            ) : (
              logs.map((log, index) => (
                <div key={index} className="mb-1 hover:bg-white/5 px-1 py-0.5">
                  <span className="text-gray-500">
                    [{formatTimestamp(log.timestamp)}]
                  </span>
                  <span className={`${getLevelColor(log.level)} ml-2`}>
                    [{log.level}]
                  </span>
                  <span className="text-gray-300 ml-2">{log.message}</span>
                </div>
              ))
            )}
          </div>

          {/* Footer Info */}
          <div className="mt-3 flex justify-between items-center text-xs text-gray-500">
            <span>Auto-refresh every 5 seconds</span>
            <span>Showing last 1000 logs</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AgentPage;
