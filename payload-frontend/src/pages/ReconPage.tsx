import { useState, useCallback, useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";
import ExploitGenerationCard from "@/components/ExploitGenerationCard";
import FingerprintTable from "@/components/FingerprintTable";
import GuideCard from "@/components/GuideCard";
import ReconTargetCard from "@/components/ReconTargetCard";
import ScanLogCard from "@/components/ScanLogCard";
import { http } from "@/utils/http";
import { toast } from "@/utils/toast";

// Navigation state interface for data from history page
interface HistoryNavigationState {
  fromHistory: boolean;
  target_ip: string;
  scan_name: string;
  os_info: OSInfo | null;
  services: any[];
  selectedServiceIndex: number;
  selectedServiceAnalysis: string | null;
}

interface OSInfo {
  name: string;
  accuracy: number;
  family: string;
  vendor: string;
  os_gen: string;
}

interface ScanProgress {
  scan_id: string;
  status: string;
  progress?: {
    current_stage?: number;
    files_scanned?: number;
    total_files?: number;
    vulnerabilities_found?: number;
    exploits_generated?: number;
    current_file?: string | null;
  };
  project_name?: string;
  started_at?: string;
}

// Helper functions for progress display
const getStatusColor = (status: string) => {
  switch (status) {
    case "completed":
      return "text-green-500";
    case "failed":
      return "text-red-500";
    case "cancelled":
      return "text-yellow-500";
    case "stage-1":
    case "stage-2":
    case "stage-3":
      return "text-blue-500";
    default:
      return "text-gray-500";
  }
};

const getStageLabel = (status: string) => {
  switch (status) {
    case "pending":
      return "Initializing...";
    case "stage-1":
      return "Stage 1: Scanning";
    case "stage-2":
      return "Stage 2: Generating Exploits";
    case "stage-3":
      return "Stage 3: Fuzzing & Optimization";
    case "completed":
      return "Completed";
    case "failed":
      return "Failed";
    case "cancelled":
      return "Cancelled";
    default:
      return status;
  }
};

// localStorage persistence for scan state
const RECON_STORAGE_KEY = "recon_current_scan";

interface StoredReconScan {
  scan_id: string;
  project_name: string;
  status: string;
  started_at: string;
  last_updated: string;
  target_ip?: string;
}

const saveReconScanToStorage = (scan: ScanProgress, targetIp?: string) => {
  try {
    localStorage.setItem(
      RECON_STORAGE_KEY,
      JSON.stringify({
        scan_id: scan.scan_id,
        project_name: scan.project_name || "Recon Target",
        status: scan.status,
        started_at: scan.started_at || new Date().toISOString(),
        last_updated: new Date().toISOString(),
        target_ip: targetIp,
      })
    );
  } catch (error) {
    console.error("Failed to save recon scan to localStorage:", error);
  }
};

const loadReconScanFromStorage = (): StoredReconScan | null => {
  try {
    const stored = localStorage.getItem(RECON_STORAGE_KEY);
    return stored ? JSON.parse(stored) : null;
  } catch (error) {
    console.error("Failed to load recon scan from localStorage:", error);
    return null;
  }
};

const clearReconScanFromStorage = () => {
  try {
    localStorage.removeItem(RECON_STORAGE_KEY);
  } catch (error) {
    console.error("Failed to clear recon scan from localStorage:", error);
  }
};

const ReconPage = () => {
  const location = useLocation();

  // State management
  const [targetIp, setTargetIp] = useState("");
  const [appName, setAppName] = useState("");
  const [services, setServices] = useState<any[]>([]);
  const [osInfo, setOsInfo] = useState<OSInfo | null>(null);
  const [analysis, setAnalysis] = useState("");
  const [mode, setMode] = useState<"whitebox" | "blackbox">("whitebox");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  // single-selection index (radio-style)
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [acknowledgmentChecked, setAcknowledgmentChecked] = useState(false);
  const [processingProgress, setProcessingProgress] = useState<{
    current: number;
    total: number;
  } | null>(null);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const pollingIntervalRef = useRef<ReturnType<typeof setInterval> | null>(
    null
  );
  const hasPrefilledFromHistory = useRef(false);

  // Prefill from history navigation state
  useEffect(() => {
    const state = location.state as HistoryNavigationState | null;

    if (state?.fromHistory && !hasPrefilledFromHistory.current) {
      hasPrefilledFromHistory.current = true;

      // Prefill form fields
      if (state.target_ip) setTargetIp(state.target_ip);
      if (state.scan_name) setAppName(state.scan_name);
      if (state.os_info) setOsInfo(state.os_info);
      if (state.services) setServices(state.services);

      // Select the clicked service (single index)
      if (typeof state.selectedServiceIndex === "number") {
        setSelectedIndex(state.selectedServiceIndex);
      }

      // Show the analysis/guide for the selected service
      if (state.selectedServiceAnalysis) {
        setAnalysis(state.selectedServiceAnalysis);
      }

      toast.success(
        "Loaded from history",
        `Viewing data for ${state.scan_name || state.target_ip}`
      );
    }
  }, [location.state]);

  // Polling functions
  const stopPolling = useCallback(() => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }
  }, []);

  const startPolling = useCallback(
    (scanId: string) => {
      stopPolling();
      pollingIntervalRef.current = setInterval(async () => {
        try {
          const response = await http.get(`/scans/${scanId}/status`);
          if (response.data.success) {
            const scanData = response.data.data;
            setScanProgress(scanData);

            // Save to localStorage for persistence
            saveReconScanToStorage(scanData, undefined);

            // Stop polling if scan finished
            if (
              ["completed", "failed", "cancelled"].includes(scanData.status)
            ) {
              stopPolling();
              setIsAnalyzing(false);
              // Keep for display but mark finished
              saveReconScanToStorage(scanData, undefined);
              if (scanData.status === "completed") {
                toast.success(
                  "Attack completed",
                  "View results in the Findings page"
                );
              } else if (scanData.status === "failed") {
                toast.error("Attack failed", "Check logs for details");
              }
            }
          }
        } catch (error) {
          console.error("Polling error:", error);
        }
      }, 2000);
    },
    [stopPolling]
  );

  // Cleanup on unmount
  useEffect(() => {
    return () => stopPolling();
  }, [stopPolling]);

  // Load saved scan on mount and resume polling if in-progress
  useEffect(() => {
    const storedScan = loadReconScanFromStorage();
    if (storedScan) {
      console.log(
        "[ReconPage] Found stored scan:",
        storedScan.scan_id,
        storedScan.status
      );

      // Set the currentScanId for logs
      setCurrentScanId(storedScan.scan_id);

      // If scan was in-progress, resume polling
      const inProgressStatuses = ["pending", "stage-1", "stage-2", "stage-3"];
      if (inProgressStatuses.includes(storedScan.status)) {
        console.log("[ReconPage] Resuming polling for in-progress scan");
        setIsAnalyzing(true);
        setScanProgress({
          scan_id: storedScan.scan_id,
          status: storedScan.status,
          project_name: storedScan.project_name,
          started_at: storedScan.started_at,
        });
        startPolling(storedScan.scan_id);
      } else {
        // Scan finished, show last result but don't poll
        setScanProgress({
          scan_id: storedScan.scan_id,
          status: storedScan.status,
          project_name: storedScan.project_name,
          started_at: storedScan.started_at,
        });
      }

      // Restore target IP if saved
      if (storedScan.target_ip) {
        setTargetIp(storedScan.target_ip);
      }
    }
  }, [startPolling]);

  // Single-select handler (row click or radio) - generates guide for selected service
  const handleServiceSelect = async (index: number | null) => {
    // Toggle: clicking the same row deselects it
    if (selectedIndex === index) {
      setSelectedIndex(null);
      setAnalysis("");
      return;
    }

    setSelectedIndex(index);

    if (index === null) return;

    const selectedService = services[index];
    if (!selectedService) return;

    setAnalysis("🔄 Generating simulation setup guide...");

    try {
      const response = await http.post("/recon/simulation-setup", {
        service: selectedService,
        os_info: osInfo,
      });

      if (response.data.success) {
        setAnalysis(response.data.data.formatted_guide);
        toast.success(
          "Setup Guide Ready",
          `Generated lab setup for ${
            selectedService.product || selectedService.service
          }`
        );
      } else {
        setAnalysis("Failed to generate setup guide. Please try again.");
      }
    } catch (error: any) {
      console.error("Simulation setup error:", error);
      setAnalysis(
        `Error: ${
          error.response?.data?.message || error.message
        }\n\nPlease ensure the Python backend is running.`
      );
    } finally {
      setAcknowledgmentChecked(false);
    }
  };

  // Acknowledgment handler
  const handleAcknowledgmentChange = (checked: boolean) => {
    setAcknowledgmentChecked(checked);
  };

  // Scan handler - no more auto-analyze, setup generated on port selection
  const handleScan = async () => {
    if (!targetIp.trim()) {
      toast.error("Target IP required", "Please enter a target IP address");
      return;
    }

    setIsScanning(true);
    setOsInfo(null);
    setSelectedIndex(null);
    setAnalysis("");

    try {
      const response = await http.post("/recon/scan", {
        target_ip: targetIp,
        application_name: appName || "Unknown Target",
      });

      if (response.data.success) {
        setServices(response.data.data.services);

        // Set OS info if available
        if (response.data.data.os_info) {
          setOsInfo(response.data.data.os_info);
        }

        toast.success(
          "Scan complete",
          `Found ${response.data.data.services.length} services. Click on a port to generate setup guide.`
        );

        // Show hint to user
        if (response.data.data.services.length > 0) {
          setAnalysis(
            "👆 Click on a discovered service/port above to generate a simulation setup guide."
          );
        }
      }
    } catch (error: any) {
      toast.error(
        "Scan failed",
        error.response?.data?.message || error.message
      );
    } finally {
      setIsScanning(false);
    }
  };

  // Blackbox handler
  const handleBlackbox = async () => {
    if (!targetIp.trim()) {
      toast.error("Target IP required", "Please enter a target IP address");
      return;
    }

    setIsAnalyzing(true);
    try {
      const response = await http.post("/recon/blackbox", {
        target_ip: targetIp,
        services: services,
      });

      if (response.data.success) {
        const formatted = response.data.data.results
          .map(
            (r: any) =>
              `Port ${r.port}: ${r.service}\nCVEs: ${r.cve_matches
                .map((c: any) => c.cve_id)
                .join(", ")}\nExploits: ${r.exploits.length} available\n`
          )
          .join("\n");
        setAnalysis(formatted);
        toast.success("Blackbox analysis complete");
      }
    } catch (error: any) {
      toast.error(
        "Analysis failed",
        error.response?.data?.message || error.message
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Poll for scan completion
  const pollScanCompletion = useCallback(
    async (scanId: string): Promise<boolean> => {
      const maxAttempts = 600; // 10 minutes max (every 1 second)
      let attempts = 0;

      while (attempts < maxAttempts) {
        try {
          const response = await http.get(`/scan/status/${scanId}`);
          const status = response.data.data?.status || response.data.status;

          if (status === "completed") {
            return true;
          } else if (status === "failed" || status === "cancelled") {
            return false;
          }

          // Wait 1 second before polling again
          await new Promise((resolve) => setTimeout(resolve, 1000));
          attempts++;
        } catch (error) {
          console.error("Polling error:", error);
          await new Promise((resolve) => setTimeout(resolve, 2000));
          attempts++;
        }
      }

      return false; // Timeout
    },
    []
  );

  // Whitebox handler with sequential port processing
  const handleWhitebox = async () => {
    if (!selectedFile) {
      toast.error("ZIP file required", "Please select a source code ZIP file");
      return;
    }

    if (!targetIp.trim()) {
      toast.error("Target IP required", "Please enter a target IP address");
      return;
    }

    // Get the single selected port or fallback to first or 8080
    const portsToProcess =
      selectedIndex !== null
        ? [services[selectedIndex]?.port].filter(Boolean)
        : services.length > 0
        ? [services[0].port]
        : [8080];

    if (portsToProcess.length === 0) {
      toast.error(
        "No ports selected",
        "Please select at least one port to attack"
      );
      return;
    }

    // IMPORTANT: Clear old scan data before starting a new scan
    clearReconScanFromStorage();
    setCurrentScanId(null);
    setScanProgress(null);
    stopPolling();

    setIsAnalyzing(true);
    const totalPorts = portsToProcess.length;

    try {
      // Process each port sequentially
      for (let i = 0; i < totalPorts; i++) {
        const port = portsToProcess[i];
        setProcessingProgress({ current: i + 1, total: totalPorts });

        toast.info(
          `Processing port ${i + 1} of ${totalPorts}`,
          `Starting full scan cycle for port ${port}...`
        );

        // Create FormData for file upload
        const uploadData = new FormData();
        uploadData.append("zipFile", selectedFile);
        uploadData.append("targetIp", targetIp);
        uploadData.append("targetPort", String(port));
        uploadData.append("applicationName", appName || "Whitebox Target");
        uploadData.append("attackMode", "true");
        uploadData.append("autoExec", "true");
        uploadData.append("demoMode", "false");

        const response = await http.post("/recon/whitebox/upload", uploadData, {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        });

        if (!response.data.success) {
          toast.error(`Port ${port} failed`, "Continuing to next port...");
          continue;
        }

        const scanId = response.data.data.scan_id;
        setCurrentScanId(scanId); // Track current scan for logs
        const initialProgress: ScanProgress = {
          scan_id: scanId,
          status: "pending",
          project_name: appName || "Whitebox Target",
        };
        setScanProgress(initialProgress);
        saveReconScanToStorage(initialProgress, targetIp); // Save to localStorage
        startPolling(scanId); // Start polling for progress updates
        toast.success(`Port ${port} scan started`, `Scan ID: ${scanId}`);

        // For last port, just show completion message (stay on ReconPage with progress box)
        if (i === totalPorts - 1) {
          toast.success(
            "All ports submitted",
            `Monitoring scan progress for port ${port}...`
          );
          // Stay on ReconPage - progress box will show status via polling
          return;
        }

        // Wait for scan to complete before proceeding to next port
        toast.info(`Waiting for port ${port} scan to complete...`);
        const completed = await pollScanCompletion(scanId);

        if (completed) {
          toast.success(
            `Port ${port} scan completed`,
            `Moving to next port...`
          );
        } else {
          toast.warning(
            `Port ${port} scan may have issues`,
            `Continuing to next port...`
          );
        }
      }
    } catch (error: any) {
      toast.error(
        "Whitebox workflow failed",
        error.response?.data?.message || error.message
      );
    } finally {
      setIsAnalyzing(false);
      setProcessingProgress(null);
    }
  };

  return (
    <div>
      <div className="overflow-auto text-white pb-6">
        <div className="mx-auto px-24 space-y-6">
          <div className="glassmorphism-card">
            <ReconTargetCard
              targetIp={targetIp}
              setTargetIp={setTargetIp}
              appName={appName}
              setAppName={setAppName}
              onScan={handleScan}
              isScanning={isScanning}
            />
          </div>

          {/* Fingerprints Table with OS Info */}
          <div>
            <FingerprintTable
              services={services}
              osInfo={osInfo}
              selectedIndex={selectedIndex}
              onServiceSelect={handleServiceSelect}
            />
          </div>

          {/* Scan Progress Box - Detailed */}
          {(scanProgress || processingProgress) && (
            <div className="glassmorphism-card rounded-xl p-6 border border-blue-500/30 bg-blue-500/5">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  {!["completed", "failed", "cancelled"].includes(
                    scanProgress?.status || ""
                  ) && (
                    <div className="animate-spin w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full" />
                  )}
                  <h2 className="text-lg font-semibold text-white">
                    {scanProgress ? "Attack Progress" : "Processing Ports"}
                  </h2>
                </div>
                <div className="flex items-center space-x-3">
                  {scanProgress && (
                    <span
                      className={`text-sm font-medium ${getStatusColor(
                        scanProgress.status
                      )}`}
                    >
                      {getStageLabel(scanProgress.status)}
                    </span>
                  )}
                  {/* Always show New Scan button to clear old data */}
                  <button
                    onClick={() => {
                      // Clear all scan-related state
                      setScanProgress(null);
                      setCurrentScanId(null);
                      clearReconScanFromStorage();
                      stopPolling();

                      // Also reset form state for a completely fresh start
                      setServices([]);
                      setOsInfo(null);
                      setSelectedIndex(null);
                      setAnalysis("");
                      setSelectedFile(null);
                      setAcknowledgmentChecked(false);
                      setProcessingProgress(null);
                      setIsAnalyzing(false);

                      toast.success(
                        "Ready for New Scan",
                        "All old data cleared. Enter a new target to begin."
                      );
                    }}
                    className="px-3 py-1.5 bg-red-600/80 hover:bg-red-500 text-white text-xs rounded transition-colors font-medium"
                    title="Clear all old data and start completely fresh"
                  >
                    🔄 New Scan
                  </button>
                </div>
              </div>

              {/* Port processing progress */}
              {processingProgress && (
                <div className="mb-4 p-3 bg-black/30 rounded-lg">
                  <p className="text-blue-400 font-medium">
                    Processing port {processingProgress.current} of{" "}
                    {processingProgress.total}
                  </p>
                </div>
              )}

              {/* Detailed scan progress */}
              {scanProgress && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-black/30 rounded-lg p-3">
                      <p className="text-gray-400 text-sm mb-1">Scan ID</p>
                      <p className="text-white font-mono text-sm truncate">
                        {scanProgress.scan_id}
                      </p>
                    </div>
                    <div className="bg-black/30 rounded-lg p-3">
                      <p className="text-gray-400 text-sm mb-1">Target</p>
                      <p className="text-white text-sm">{targetIp}</p>
                    </div>
                  </div>

                  {scanProgress.progress && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="bg-black/30 rounded-lg p-3">
                        <p className="text-gray-400 text-sm mb-1">
                          Files Scanned
                        </p>
                        <p className="text-white text-xl font-semibold">
                          {scanProgress.progress.files_scanned || 0}
                        </p>
                      </div>
                      <div className="bg-black/30 rounded-lg p-3">
                        <p className="text-gray-400 text-sm mb-1">
                          Vulnerabilities
                        </p>
                        <p className="text-red-400 text-xl font-semibold">
                          {scanProgress.progress.vulnerabilities_found || 0}
                        </p>
                      </div>
                      <div className="bg-black/30 rounded-lg p-3">
                        <p className="text-gray-400 text-sm mb-1">Exploits</p>
                        <p className="text-yellow-400 text-xl font-semibold">
                          {scanProgress.progress.exploits_generated || 0}
                        </p>
                      </div>
                      <div className="bg-black/30 rounded-lg p-3">
                        <p className="text-gray-400 text-sm mb-1">Stage</p>
                        <p className="text-blue-400 text-xl font-semibold">
                          {scanProgress.progress.current_stage || 0}/3
                        </p>
                      </div>
                    </div>
                  )}

                  {scanProgress.progress?.current_file && (
                    <div className="bg-black/30 rounded-lg p-3">
                      <p className="text-gray-400 text-sm mb-1">Current File</p>
                      <p className="text-white text-sm font-mono truncate">
                        {scanProgress.progress.current_file}
                      </p>
                    </div>
                  )}

                  {/* Dismiss button for completed/failed scans */}
                  {["completed", "failed", "cancelled"].includes(
                    scanProgress.status
                  ) && (
                    <div className="flex justify-end mt-4">
                      <button
                        onClick={() => {
                          setScanProgress(null);
                          setCurrentScanId(null);
                          clearReconScanFromStorage();
                        }}
                        className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-lg transition-colors"
                      >
                        Dismiss
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Guide Card */}
          <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
            <GuideCard
              analysis={analysis}
              acknowledgmentChecked={acknowledgmentChecked}
              onAcknowledgmentChange={handleAcknowledgmentChange}
            />
          </div>

          {/* Exploit Generation Window */}
          <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
            <ExploitGenerationCard
              mode={mode}
              setMode={setMode}
              selectedFile={selectedFile}
              onFileSelect={setSelectedFile}
              onGenerate={mode === "whitebox" ? handleWhitebox : handleBlackbox}
              isGenerating={isAnalyzing}
              disabled={!acknowledgmentChecked}
            />
          </div>

          {/* Scan Logs */}
          <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
            <ScanLogCard scanId={currentScanId} isScanning={isAnalyzing} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReconPage;
