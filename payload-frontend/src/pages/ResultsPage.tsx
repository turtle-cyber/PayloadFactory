import { useEffect, useState, useRef } from "react";
import { http } from "../utils/http";
import { GET_SCANS } from "../endpoints/resultspage.endpoints";
import { toast } from "../utils/toast";
import { useNavigate } from "react-router-dom";

interface ApiScanData {
  id: string;
  project_name: string;
  file_size: number;
  root_path: string;
  scan_status: string;
  submitted_at: string;
  date: string;
  execution_time: string | null;
}

interface ScanFinding {
  id: string;
  name: string;
  size: string;
  fileLocation: string;
  status: string;
  executionTime: string;
  date: string;
  runTime: string;
}

function useGetScans() {
  const [scanData, setScanData] = useState<ApiScanData[]>([]);
  const [scanLoading, setScanLoading] = useState(false);
  const hasFetched = useRef(false);

  const fetchScans = async () => {
    setScanLoading(true);
    try {
      const response = await http.get(GET_SCANS);

      // Handle API response structure
      const data = response?.data?.hits || [];
      const scansArray = Array.isArray(data) ? data : [];

      setScanData(scansArray);

      if (scansArray.length > 0) {
        toast.success(
          "Scans loaded successfully",
          `Found ${scansArray.length} scan(s)`
        );
      }
    } catch (error) {
      toast.error("Error fetching scans", "Failed to load scan data");
      console.error("Error fetching scans:", error);
      setScanData([]);
    } finally {
      setScanLoading(false);
    }
  };

  useEffect(() => {
    if (!hasFetched.current) {
      hasFetched.current = true;
      fetchScans();
    }
  }, []);

  return { scanData, scanLoading, fetchScans };
}

// Skeleton loader component
const SkeletonRow = () => (
  <tr className="border-b border-white/5 animate-pulse">
    <td className="py-4 px-4">
      <div className="h-4 bg-white/10 rounded w-32"></div>
    </td>
    <td className="py-4 px-4">
      <div className="h-4 bg-white/10 rounded w-16"></div>
    </td>
    <td className="py-4 px-4">
      <div className="h-4 bg-white/10 rounded w-48"></div>
    </td>
    <td className="py-4 px-4">
      <div className="h-4 bg-white/10 rounded w-20"></div>
    </td>
    <td className="py-4 px-4">
      <div className="h-4 bg-white/10 rounded w-24"></div>
    </td>
    <td className="py-4 px-4">
      <div className="h-4 bg-white/10 rounded w-16"></div>
    </td>
  </tr>
);

// Helper to format file size
const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

const formatStatus = (status: string) => {
  const formattedStatus = status.toLowerCase();
  if (formattedStatus === "completed") {
    return "bg-green-500/20 text-green-400";
  } else if (formattedStatus === "failed") {
    return "bg-red-500/20 text-red-400";
  } else if (formattedStatus === "stage-1") {
    return "bg-yellow-500/20 text-yellow-400";
  } else if (formattedStatus === "stage-2") {
    return "bg-orange-500/20 text-orange-400";
  } else if (formattedStatus === "stage-3") {
    return "bg-blue-500/20 text-blue-400";
  } else {
    return "bg-gray-500/20 text-gray-400";
  }
};

const ResultsPage: React.FC = () => {
  const { scanData, scanLoading, fetchScans } = useGetScans();
  const navigate = useNavigate();

  // Map API response to table format
  const findings: ScanFinding[] = scanData.map((scan) => ({
    id: scan.id,
    name: scan.project_name || "Unknown",
    size: formatFileSize(scan.file_size),
    status: scan.scan_status || "N/A",
    fileLocation: scan.root_path || "N/A",
    executionTime: scan.execution_time || "Pending",
    date: scan.date || "N/A",
    runTime: scan.execution_time || "Pending",
  }));

  const handleRowClick = (id: string) => {
    navigate(`/results/${id}`);
  };

  return (
    <div className="overflow-auto text-white">
      <div className="max-w-6xl mx-auto px-6">
        {/* Findings Section */}
        <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-xl font-semibold text-gray-400">
              Findings
              {!scanLoading && findings.length > 0 && (
                <span className="text-xl text-gray-500 ml-2">
                  ({findings.length})
                </span>
              )}
            </h2>
            {!scanLoading && (
              <button
                onClick={fetchScans}
                className="px-4 py-2 text-sm bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition-colors flex items-center gap-2"
              >
                <svg
                  className="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                  />
                </svg>
                Refresh
              </button>
            )}
          </div>

          {/* Table */}
          <div className="overflow-x-auto max-h-[70vh] overflow-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left py-4 px-4 text-gray-400 font-medium text-sm">
                    Name
                  </th>
                  <th className="text-left py-4 px-4 text-gray-400 font-medium text-sm">
                    Size
                  </th>
                  <th className="text-left py-4 px-4 text-gray-400 font-medium text-sm">
                    File Location
                  </th>
                  <th className="text-left py-4 px-4 text-gray-400 font-medium text-sm">
                    Status
                  </th>
                  <th className="text-left py-4 px-4 text-gray-400 font-medium text-sm">
                    Date
                  </th>
                  <th className="text-left py-4 px-4 text-gray-400 font-medium text-sm">
                    Execution Time
                  </th>
                </tr>
              </thead>
              <tbody>
                {scanLoading ? (
                  // Show skeleton rows while loading
                  <>
                    <SkeletonRow />
                    <SkeletonRow />
                    <SkeletonRow />
                    <SkeletonRow />
                    <SkeletonRow />
                  </>
                ) : findings.length > 0 ? (
                  // Show actual data
                  findings.map((finding) => (
                    <tr
                      key={finding.id}
                      className="border-b border-white/5 hover:bg-white/5 transition-colors cursor-pointer"
                      onClick={() => {
                        handleRowClick(finding.id);
                      }}
                    >
                      <td className="py-4 px-4 text-white">{finding.name}</td>
                      <td className="py-4 px-4 text-gray-400">
                        {finding.size}
                      </td>
                      <td
                        className="py-4 px-4 text-gray-400 max-w-xs truncate"
                        title={finding.fileLocation}
                      >
                        {finding.fileLocation}
                      </td>
                      <td className="py-4 px-4">
                        <span
                          className={`px-2 py-1 rounded text-xs ${formatStatus(
                            finding.status
                          )}`}
                        >
                          {finding.status.charAt(0).toUpperCase() +
                            finding.status.slice(1)}
                        </span>
                      </td>
                      <td className="py-4 px-4 text-gray-400">
                        {finding.date}
                      </td>
                      <td className="py-4 px-4 text-gray-400">
                        {finding.runTime}
                      </td>
                    </tr>
                  ))
                ) : (
                  // Show empty state
                  <tr>
                    <td colSpan={6} className="py-12 text-center">
                      <div className="flex flex-col items-center justify-center text-gray-500">
                        <svg
                          className="w-16 h-16 mb-4 opacity-50"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={1.5}
                            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                          />
                        </svg>
                        <p className="text-lg mb-2">No scans found</p>
                        <p className="text-sm">
                          Run a scan to see results here
                        </p>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ResultsPage;
