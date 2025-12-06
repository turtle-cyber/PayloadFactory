import { useEffect, useRef, useState } from "react";
import { Download } from "lucide-react";
import { http } from "../utils/http";
import { GET_FINDINGS } from "../endpoints/resultspage.endpoints";
import { toast } from "sonner";
import { useParams } from "react-router-dom";

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
      console.log(response);

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

  const [selectedSeverity, setSelectedSeverity] = useState<
    "All" | "Critical" | "High" | "Medium" | "Low"
  >("All");

  const findings = findingData?.findings || [];
  const severityCounts = findingData?.counts || {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };

  const filteredFindings =
    selectedSeverity === "All"
      ? findings
      : findings.filter((finding) => finding.severity === selectedSeverity);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "text-red-500";
      case "High":
        return "text-orange-500";
      case "Medium":
        return "text-yellow-500";
      case "Low":
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

  return (
    <div className="">
      <div className="max-w-6xl mx-auto flex gap-6">
        {/* Left Sidebar - Scan Summary */}
        <div className="w-[25%]">
          <div className="glassmorphism-card rounded-lg p-4 border border-red-500/20">
            <h2 className="text-lg font-semibold mb-2">Scan Summary</h2>
            <div className="space-y-2">
              {/* Total Findings */}
              <button
                onClick={() => setSelectedSeverity("All")}
                className={`w-full flex justify-between items-center p-2 rounded-lg transition-all cursor-pointer ${
                  selectedSeverity === "All"
                    ? "bg-gray-700/50 border-2 border-gray-500"
                    : "hover:bg-gray-800/30 border-2 border-transparent"
                }`}
              >
                <span className="text-sm text-gray-300">Total Findings</span>
                <span className="bg-gray-700 px-3 py-1 rounded-full text-sm font-semibold">
                  {severityCounts.total}
                </span>
              </button>

              {/* Critical */}
              <button
                onClick={() => setSelectedSeverity("Critical")}
                className={`w-full flex justify-between items-center p-2 rounded-lg transition-all cursor-pointer ${
                  selectedSeverity === "Critical"
                    ? "bg-red-900/30 border-2 border-red-500"
                    : "hover:bg-red-900/10 border-2 border-transparent"
                }`}
              >
                <span className="text-sm text-red-500">Critical</span>
                <span className="bg-red-900/30 px-3 py-1 rounded-full text-sm font-semibold text-red-400">
                  {severityCounts.critical}
                </span>
              </button>

              {/* High */}
              <button
                onClick={() => setSelectedSeverity("High")}
                className={`w-full flex justify-between items-center p-2 rounded-lg transition-all cursor-pointer ${
                  selectedSeverity === "High"
                    ? "bg-orange-900/30 border-2 border-orange-500"
                    : "hover:bg-orange-900/10 border-2 border-transparent"
                }`}
              >
                <span className="text-sm text-orange-500">High</span>
                <span className="bg-orange-900/30 px-3 py-1 rounded-full text-sm font-semibold text-orange-400">
                  {severityCounts.high}
                </span>
              </button>

              {/* Medium */}
              <button
                onClick={() => setSelectedSeverity("Medium")}
                className={`w-full flex justify-between items-center p-2 rounded-lg transition-all cursor-pointer ${
                  selectedSeverity === "Medium"
                    ? "bg-yellow-900/30 border-2 border-yellow-500"
                    : "hover:bg-yellow-900/10 border-2 border-transparent"
                }`}
              >
                <span className="text-sm text-gray-500">Medium</span>
                <span className="bg-gray-700 px-3 py-1 rounded-full text-sm font-semibold text-gray-400">
                  {severityCounts.medium}
                </span>
              </button>

              {/* Low */}
              <button
                onClick={() => setSelectedSeverity("Low")}
                className={`w-full flex justify-between items-center p-2 rounded-lg transition-all cursor-pointer ${
                  selectedSeverity === "Low"
                    ? "bg-cyan-900/30 border-2 border-cyan-500"
                    : "hover:bg-cyan-900/10 border-2 border-transparent"
                }`}
              >
                <span className="text-sm text-gray-500">Low</span>
                <span className="bg-gray-700 px-3 py-1 rounded-full text-sm font-semibold text-gray-400">
                  {severityCounts.low}
                </span>
              </button>
            </div>
          </div>
        </div>

        {/* Main Content - Findings Table */}
        <div className="w-[75%]">
          {/* Header with buttons */}
          <div className="glassmorphism-card rounded-lg p-4 border border-red-500/20 mb-4">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-semibold">Findings</h2>
              {/* <div className="flex gap-2">
                <button className="border border-gray-600 hover:border-red-500 rounded-lg px-4 py-2 text-sm transition-colors flex items-center gap-2">
                  <span className="text-gray-500">
                    <Trash className="w-5" />
                  </span>
                  Clear Results
                </button>
                <button className="border border-gray-600 hover:border-red-500 rounded-lg px-4 py-2 text-sm transition-colors flex items-center gap-2">
                  <span className="text-gray-500">
                    <Share className="w-5" />
                  </span>
                  Export Results
                </button>
                <button className="border border-gray-600 hover:border-red-500 rounded-lg px-4 py-2 text-sm transition-colors flex items-center gap-2">
                  <span className="text-gray-500">
                    <Bandage className="w-5" />
                  </span>
                  Generate Patches
                </button>
              </div> */}
            </div>
          </div>

          {/* Findings Table */}
          <div className="glassmorphism-card rounded-lg border border-red-500/20 max-h-[70vh] overflow-auto">
            {findingLoading ? (
              <div className="flex items-center justify-center py-20">
                <div className="text-center">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500 mx-auto mb-4"></div>
                  <p className="text-gray-400">Loading findings...</p>
                </div>
              </div>
            ) : filteredFindings.length === 0 ? (
              <div className="flex items-center justify-center py-20">
                <div className="text-center">
                  <p className="text-gray-400 text-lg mb-2">
                    No findings available
                  </p>
                  <p className="text-gray-500 text-sm">
                    {selectedSeverity !== "All"
                      ? `No ${selectedSeverity.toLowerCase()} severity findings found`
                      : "No vulnerability findings for this scan"}
                  </p>
                </div>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left p-4 text-sm font-semibold text-gray-400">
                        Severity
                      </th>
                      <th className="text-left p-4 text-sm font-semibold text-gray-400">
                        CWE
                      </th>
                      <th className="text-left p-4 text-sm font-semibold text-gray-400">
                        CVE
                      </th>
                      <th className="text-left p-4 text-sm font-semibold text-gray-400">
                        File
                      </th>
                      <th className="text-left p-4 text-sm font-semibold text-gray-400">
                        Line
                      </th>
                      <th className="text-left p-4 text-sm font-semibold text-gray-400">
                        Confidence
                      </th>
                      <th className="text-left p-4 text-sm font-semibold text-gray-400">
                        Download Exploit
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFindings.map((finding, index) => (
                      <tr
                        key={index}
                        className="border-b border-gray-800 hover:bg-gray-900/50 transition-colors"
                      >
                        <td className="p-4">
                          <span
                            className={`text-sm font-semibold ${getSeverityColor(
                              finding.severity
                            )}`}
                          >
                            {finding.severity}
                          </span>
                        </td>
                        <td className="p-4 text-sm text-gray-300">
                          {finding.cwe}
                        </td>
                        <td className="p-4 text-sm text-gray-300">
                          {finding.cve}
                        </td>
                        <td className="p-4 text-sm text-gray-300">
                          {finding.file}
                        </td>
                        <td className="p-4 text-sm text-gray-400">
                          {finding.line}
                        </td>
                        <td className="p-4 text-sm text-gray-400">
                          {finding.confidence.toFixed(3)}
                        </td>
                        <td className="p-4">
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
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default FindingPage;
