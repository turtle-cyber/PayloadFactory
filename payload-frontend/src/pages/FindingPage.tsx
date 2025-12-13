import { useEffect, useRef, useState, useCallback } from "react";
import {
  ArrowRight,
  Download,
  Trash,
  Loader2,
  MessageSquareCode,
} from "lucide-react";
import { http } from "../utils/http";
import { GET_FINDINGS, START_ATTACK } from "../endpoints/resultspage.endpoints";
import { toast } from "sonner";
import { useParams } from "react-router-dom";
import ExploitLogPopup from "@/components/ExploitLogPopup";

interface Finding {
  severity: "Critical" | "High" | "Medium" | "Low" | "Unknown";
  cwe: string;
  cve: string;
  file: string;
  line: number;
  confidence: number;
  exploit_path: string | null;
}

interface SeverityCounts {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

interface FindingResponse {
  success: boolean;
  scan_id: string;
  counts: SeverityCounts;
  findings: Finding[];
}

function useGetFindings(scan_id: string) {
  const [findingData, setFindingData] = useState<FindingResponse | null>(null);
  const [findingLoading, setFindingLoading] = useState<boolean>(false);
  const hasFetched = useRef(false);

  const fetchFindings = async () => {
    if (!scan_id) {
      setFindingLoading(false);
      return;
    }

    setFindingLoading(true);
    try {
      const response = await http.get(GET_FINDINGS, {
        params: { scan_id },
      });

      if (response.status === 200 && response.data) {
        toast.success("Findings loaded successfully");
        setFindingData(response.data);
      }
    } catch (error) {
      toast.error("Error fetching findings");
      console.error("Error fetching findings:", error);
      setFindingData(null);
    } finally {
      setFindingLoading(false);
    }
  };

  useEffect(() => {
    if (!hasFetched.current && scan_id) {
      hasFetched.current = true;
      fetchFindings();
    }
  }, [scan_id]);

  return { findingData, findingLoading, fetchFindings };
}

const FindingPage = () => {
  const { scan_id } = useParams<{ scan_id: string }>();
  const scanId = scan_id || "";

  const { findingData, findingLoading } = useGetFindings(scanId);

  const [selectedRows, setSelectedRows] = useState<Set<number>>(new Set());
  const [isLaunching, setIsLaunching] = useState<boolean>(false);

  // Exploit logs popup state
  const [exploitStatuses, setExploitStatuses] = useState<
    Record<string, string>
  >({});
  const [isPopupOpen, setIsPopupOpen] = useState(false);
  const [selectedExploit, setSelectedExploit] = useState<string>("");

  // Fetch exploit statuses after launch
  const fetchExploitStatuses = useCallback(async () => {
    if (!scanId) return;
    try {
      const response = await http.get(`/scans/${scanId}/exploit-statuses`);
      if (response.data?.success && response.data?.data?.statuses) {
        setExploitStatuses(response.data.data.statuses);
      }
    } catch (error) {
      console.error("Failed to fetch exploit statuses:", error);
    }
  }, [scanId]);

  // Poll for statuses after launch
  useEffect(() => {
    if (scanId) {
      fetchExploitStatuses();
      const interval = setInterval(fetchExploitStatuses, 5000);
      return () => clearInterval(interval);
    }
  }, [scanId, fetchExploitStatuses]);

  // Handle log icon click
  const handleViewLogs = (exploitPath: string) => {
    const filename =
      exploitPath.split("\\").pop() || exploitPath.split("/").pop() || "";
    if (!filename) return;

    setSelectedExploit(filename);
    setIsPopupOpen(true);
  };

  // Get status for an exploit
  const getExploitStatus = (exploitPath: string | null): string => {
    if (!exploitPath) return "not_started";
    const filename =
      exploitPath.split("\\").pop() || exploitPath.split("/").pop() || "";
    return exploitStatuses[filename] || "not_started";
  };

  const findings = findingData?.findings || [];
  const severityCounts = findingData?.counts || {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };

  const selectableFindings = findings
    .map((finding, index) => ({ finding, index }))
    .filter(({ finding }) => finding.exploit_path);

  const isAllSelected =
    selectableFindings.length > 0 &&
    selectableFindings.every(({ index }) => selectedRows.has(index));

  const handleSelectAll = () => {
    if (isAllSelected) {
      setSelectedRows(new Set());
    } else {
      const allIndices = new Set(selectableFindings.map(({ index }) => index));
      setSelectedRows(allIndices);
    }
  };

  const handleSelectRow = (index: number) => {
    const newSelected = new Set(selectedRows);
    if (newSelected.has(index)) {
      newSelected.delete(index);
    } else {
      newSelected.add(index);
    }
    setSelectedRows(newSelected);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "text-red-500";
      case "HIGH":
        return "text-orange-500";
      case "MEDIUM":
        return "text-yellow-500";
      case "LOW":
        return "text-cyan-500";
      default:
        return "text-gray-400";
    }
  };

  // Show error if scan_id is missing from URL
  if (!scanId) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <p className="text-red-500 text-xl mb-2">Missing Scan ID</p>
          <p className="text-gray-400">
            Please provide a scan_id in the URL path
          </p>
          <p className="text-gray-500 text-sm mt-2">
            Example: /results/your_scan_id_here
          </p>
        </div>
      </div>
    );
  }

  const handleDownload = async (path: string) => {
    try {
      // Extract filename from the path
      const filename =
        path.split("\\").pop() || path.split("/").pop() || "exploit.py";

      // Make request to download the file from the server
      const response = await http.get(`/download`, {
        params: { file_path: path },
        responseType: "blob", // Important for file downloads
      });

      // Create a blob URL and trigger download
      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();

      // Cleanup
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      toast.success(`Downloaded ${filename} successfully`);
    } catch (error) {
      toast.error("Error downloading exploit file");
      console.error("Download error:", error);
    }
  };

  const handleLaunchAttack = async () => {
    if (selectedRows.size === 0) {
      toast.error("Please select at least one exploit to launch");
      return;
    }

    // Get exploit paths from selected rows
    const selectedExploits: string[] = [];
    selectedRows.forEach((index) => {
      const finding = findings[index];
      if (finding?.exploit_path) {
        // Extract just the filename from the path
        const filename =
          finding.exploit_path.split("\\").pop() ||
          finding.exploit_path.split("/").pop();
        if (filename) {
          selectedExploits.push(filename);
        }
      }
    });

    if (selectedExploits.length === 0) {
      toast.error("No valid exploits found in selection");
      return;
    }

    setIsLaunching(true);
    try {
      toast.info(
        `Launching ${selectedExploits.length} exploit(s) for Stage 3 evolution...`
      );

      const response = await http.post(
        `${START_ATTACK}/${scanId}/start-attack`,
        {
          selected_exploits: selectedExploits,
          run_all: false,
        }
      );

      if (response.status === 200 && response.data?.success) {
        toast.success(
          `Attack started! ${selectedExploits.length} exploit(s) will be evolved and executed.`
        );
        // Clear selection after successful launch
        setSelectedRows(new Set());
      } else {
        toast.error(response.data?.message || "Failed to start attack");
      }
    } catch (error: unknown) {
      console.error("Launch attack error:", error);
      const axiosError = error as {
        response?: { data?: { message?: string } };
      };
      toast.error(
        axiosError.response?.data?.message ||
          "Error launching attack. Please try again."
      );
    } finally {
      setIsLaunching(false);
    }
  };

  return (
    <div className="">
      <div className="px-48 mx-auto flex gap-6">
        {/* Left Sidebar - Scan Summary */}
        <div className="w-[20%]">
          <div className="rounded-lg p-4">
            <h2 className="text-lg mb-4 font-mono">Finding Summary</h2>
            <div className="border border-[#30363d] rounded-lg">
              {/* Total Findings */}
              <div className="w-full flex justify-between items-center p-2">
                <span className="text-sm text-gray-300">Total Findings</span>
                <span className="bg-gray-700 px-3 py-1 rounded-full text-sm font-semibold">
                  {severityCounts.total}
                </span>
              </div>

              {/* Critical */}
              {severityCounts.critical > 0 && (
                <div className="w-full flex justify-between items-center p-2">
                  <span className="text-sm text-red-500">Critical</span>
                  <span className="bg-red-900/30 px-3 py-1 rounded-full text-sm font-semibold text-red-400">
                    {severityCounts.critical}
                  </span>
                </div>
              )}

              {/* High */}
              {severityCounts.high > 0 && (
                <div className="w-full flex justify-between items-center p-2">
                  <span className="text-sm text-orange-500">High</span>
                  <span className="bg-orange-900/30 px-3 py-1 rounded-full text-sm font-semibold text-orange-400">
                    {severityCounts.high}
                  </span>
                </div>
              )}

              {/* Medium */}
              {severityCounts.medium > 0 && (
                <div className="w-full flex justify-between items-center p-2">
                  <span className="text-sm text-yellow-500">Medium</span>
                  <span className="bg-yellow-900/30 px-3 py-1 rounded-full text-sm font-semibold text-yellow-400">
                    {severityCounts.medium}
                  </span>
                </div>
              )}

              {/* Low */}
              {severityCounts.low > 0 && (
                <div className="w-full flex justify-between items-center p-2">
                  <span className="text-sm text-cyan-500">Low</span>
                  <span className="bg-cyan-900/30 px-3 py-1 rounded-full text-sm font-semibold text-cyan-400">
                    {severityCounts.low}
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Main Content - Findings Table */}
        <div className="w-[75%]">
          {/* Header with buttons */}
          <div className="rounded-lg px-4 py-2 bg-[#2f2f2f] mb-4">
            <div className="flex justify-between items-center">
              <h2 className="text-md font-mono text-[#969696]">Findings</h2>
              {/* <div className="flex gap-2">
                <button className="px-2 py-1 text-sm transition-colors flex items-center gap-2 font-thin tracking-wide border border-gray-600 hover:border-red-500 rounded-lg">
                  <span className="text-gray-500">
                    <Trash className="w-4" />
                  </span>
                  Clear Results
                </button>
              </div> */}
            </div>
          </div>

          {/* Findings Table */}
          <div className="rounded-lg max-h-[70vh] overflow-auto bg-[#201f1c] opacity-70">
            {findingLoading ? (
              <div className="flex items-center justify-center py-20">
                <div className="text-center">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500 mx-auto mb-4"></div>
                  <p className="text-gray-400">Loading findings...</p>
                </div>
              </div>
            ) : findings.length === 0 ? (
              <div className="flex items-center justify-center py-20">
                <div className="text-center">
                  <p className="text-gray-400 text-lg mb-2">
                    No findings available
                  </p>
                  <p className="text-gray-500 text-sm">
                    No vulnerability findings for this scan
                  </p>
                </div>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-center p-4 text-sm font-semibold text-gray-400 align-middle">
                        Severity
                      </th>
                      <th className="text-center p-4 text-sm font-semibold text-gray-400 align-middle">
                        CWE
                      </th>
                      <th className="text-center p-4 text-sm font-semibold text-gray-400 align-middle">
                        CVE
                      </th>
                      <th className="text-center p-4 text-sm font-semibold text-gray-400 align-middle">
                        File
                      </th>
                      <th className="text-center p-4 text-sm font-semibold text-gray-400 align-middle">
                        Line
                      </th>
                      <th className="text-center p-4 text-sm font-semibold text-gray-400 align-middle">
                        Confidence
                      </th>
                      <th className="text-center p-4 text-sm font-semibold text-gray-400 align-middle">
                        Download Exploit
                      </th>
                      <th className="text-center p-4 text-sm font-semibold text-gray-400 align-middle">
                        <input
                          type="checkbox"
                          checked={isAllSelected}
                          onChange={handleSelectAll}
                          disabled={selectableFindings.length === 0}
                          className={`w-4 h-4 rounded border-gray-600 bg-gray-800 text-red-500 focus:ring-red-500 focus:ring-offset-0 ${
                            selectableFindings.length > 0
                              ? "cursor-pointer"
                              : "cursor-not-allowed opacity-40"
                          }`}
                        />
                      </th>
                      <th className="text-center p-4 text-sm font-semibold text-gray-400 align-middle">
                        Logs
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((finding, index) => (
                      <tr
                        key={index}
                        className="border-gray-800 border-b hover:bg-gray-900/50 transition-colors"
                      >
                        <td className="px-4 py-2 text-center align-middle">
                          <span
                            className={`text-sm font-semibold ${getSeverityColor(
                              finding.severity
                            )}`}
                          >
                            {finding.severity}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-sm text-gray-300 text-center align-middle">
                          {finding.cwe}
                        </td>
                        <td className="px-4 py-2 text-sm text-gray-300 text-center align-middle">
                          {finding.cve === "Unknown"
                            ? "Unclassified"
                            : finding.cve}
                        </td>
                        <td className="px-4 py-2 text-sm text-gray-300 text-center align-middle">
                          {finding.file}
                        </td>
                        <td className="px-4 py-2 text-sm text-gray-400 text-center align-middle">
                          {finding.line}
                        </td>
                        <td className="px-4 py-2 text-sm text-gray-400 text-center align-middle">
                          {finding.confidence.toFixed(3)}
                        </td>
                        <td className="px-4 py-2 text-center align-middle">
                          <div className="flex justify-center">
                            {finding.exploit_path ? (
                              <button
                                onClick={() =>
                                  handleDownload(finding.exploit_path!)
                                }
                                className="bg-gray-800 hover:bg-gray-700 rounded-full p-2 transition-colors"
                              >
                                <Download size={16} className="text-gray-400" />
                              </button>
                            ) : (
                              <span className="text-gray-600 text-xs">N/A</span>
                            )}
                          </div>
                        </td>
                        <td className="text-center align-middle">
                          <input
                            type="checkbox"
                            checked={selectedRows.has(index)}
                            onChange={() => handleSelectRow(index)}
                            disabled={!finding.exploit_path}
                            className={`w-4 h-4 rounded border-gray-600 bg-gray-800 text-red-500 focus:ring-red-500 focus:ring-offset-0 ${
                              finding.exploit_path
                                ? "cursor-pointer"
                                : "cursor-not-allowed opacity-40"
                            }`}
                          />
                        </td>
                        <td className="px-4 py-2 text-center align-middle">
                          <div className="flex justify-center">
                            {/* Log icon - status-based coloring */}
                            {finding.exploit_path ? (
                              <button
                                onClick={() =>
                                  handleViewLogs(finding.exploit_path!)
                                }
                                className={`p-2 rounded-full transition-colors ${
                                  getExploitStatus(finding.exploit_path) ===
                                  "completed"
                                    ? "bg-green-900/30 hover:bg-green-800/50 text-green-400"
                                    : getExploitStatus(finding.exploit_path) ===
                                      "in_progress"
                                    ? "bg-yellow-900/30 hover:bg-yellow-800/50 text-yellow-400 animate-pulse"
                                    : getExploitStatus(finding.exploit_path) ===
                                      "failed"
                                    ? "bg-red-900/30 hover:bg-red-800/50 text-red-400"
                                    : "bg-gray-800 hover:bg-gray-700 text-gray-500"
                                }`}
                                title={
                                  getExploitStatus(finding.exploit_path) ===
                                  "completed"
                                    ? "Attack completed - View logs"
                                    : getExploitStatus(finding.exploit_path) ===
                                      "in_progress"
                                    ? "Attack in progress"
                                    : getExploitStatus(finding.exploit_path) ===
                                      "failed"
                                    ? "Attack failed - View logs"
                                    : "Not executed yet"
                                }
                              >
                                <MessageSquareCode size={16} />
                              </button>
                            ) : (
                              <div className="p-2 rounded-full bg-gray-800 text-gray-600 cursor-not-allowed">
                                <MessageSquareCode size={16} />
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Launch Button */}
          <div className="flex justify-center mt-5">
            <button
              onClick={handleLaunchAttack}
              disabled={selectedRows.size === 0 || isLaunching}
              className={`border w-40 rounded-lg px-4 py-2 flex justify-center items-center gap-x-2 transition-all duration-300 ${
                selectedRows.size > 0 && !isLaunching
                  ? "bg-[#ff11111f] border-[#795a5a] text-gray-200 hover:bg-[#ff111145] hover:shadow-[0_0_20px_rgba(255,50,50,0.3)]"
                  : "bg-gray-800/30 border-gray-700 text-gray-600 cursor-not-allowed"
              }`}
            >
              {isLaunching ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Launching...</span>
                </>
              ) : (
                <>
                  <span>Weaponize</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Exploit Log Popup */}
      <ExploitLogPopup
        isOpen={isPopupOpen}
        onClose={() => setIsPopupOpen(false)}
        exploitFilename={selectedExploit}
        scanId={scanId}
      />
    </div>
  );
};

export default FindingPage;
