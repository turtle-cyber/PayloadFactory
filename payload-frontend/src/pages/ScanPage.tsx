import { useState, useEffect, useRef } from "react";
import { toast } from "../utils/toast";
import { http } from "../utils/http";
import RepositoryCard from "@/components/RepositoryCard";
import ExportSettingsCard from "@/components/ExportSettingsCard";

interface FormData {
  applicationName: string;
  maxTokenLength: string;
  batchSize: string;
  minConfidence: string;
  exportProjectPath: string;
  exportFormat: string;
  quickScan: boolean;
  demoMode: boolean;
  attackMode: boolean;
  targetIp: string;
  targetPort: string;
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
  completed_at?: string;
}

interface StoredScan {
  scan_id: string;
  project_name: string;
  status: string;
  started_at: string;
  last_updated: string;
}

// localStorage helper functions
const STORAGE_KEY = "payloadfactory_active_scan";

const saveScanToStorage = (scan: ScanProgress) => {
  try {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        scan_id: scan.scan_id,
        project_name: scan.project_name || "Unknown",
        status: scan.status,
        started_at: scan.started_at || new Date().toISOString(),
        last_updated: new Date().toISOString(),
      })
    );
  } catch (error) {
    console.error("Failed to save scan to localStorage:", error);
  }
};

const loadScanFromStorage = (): StoredScan | null => {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored ? JSON.parse(stored) : null;
  } catch (error) {
    console.error("Failed to load scan from localStorage:", error);
    return null;
  }
};

const clearScanFromStorage = () => {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (error) {
    console.error("Failed to clear scan from localStorage:", error);
  }
};

const ScanPage: React.FC = () => {
  const [formData, setFormData] = useState<FormData>({
    applicationName: "My App",
    maxTokenLength: "512",
    batchSize: "32",
    minConfidence: "0.3",
    exportProjectPath: "",
    exportFormat: "Excel.xlsx",
    quickScan: false,
    demoMode: false,
    attackMode: false,
    targetIp: "",
    targetPort: "",
  });

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
    };
  }, []);

  // Recover scan from localStorage on mount
  useEffect(() => {
    const recoverScan = async () => {
      const storedScan = loadScanFromStorage();
      if (storedScan) {
        try {
          // Fetch current status from backend
          const response = await http.get(
            `/scans/${storedScan.scan_id}/status`
          );
          if (response.data.success) {
            const scanData = response.data.data;
            setScanProgress(scanData);

            // Resume polling if scan is still active
            const activeStatuses = ["pending", "stage-1", "stage-2", "stage-3"];
            if (activeStatuses.includes(scanData.status)) {
              setIsScanning(true);
              startPolling(storedScan.scan_id);
            }
          }
        } catch (error) {
          console.error("Failed to recover scan:", error);
          // If scan not found, clear storage
          clearScanFromStorage();
        }
      }
    };

    recoverScan();
  }, []);

  // Start polling for scan progress
  const startPolling = (scanId: string) => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
    }

    pollingIntervalRef.current = setInterval(async () => {
      try {
        const response = await http.get(`/scans/${scanId}/status`);
        if (response.data.success) {
          const scanData = response.data.data;
          setScanProgress(scanData);

          // Save to localStorage on each update
          saveScanToStorage(scanData);

          // Stop polling if scan is completed, failed, or cancelled
          const status = scanData.status;
          if (
            status === "completed" ||
            status === "failed" ||
            status === "cancelled"
          ) {
            stopPolling();
            setIsScanning(false);

            if (status === "completed") {
              toast.success(
                "Scan completed",
                "Your vulnerability scan has finished successfully"
              );
            } else if (status === "failed") {
              toast.error("Scan failed", "The scan encountered an error");
            }
          }
        }
      } catch (error) {
        console.error("Error fetching scan status:", error);
      }
    }, 2000); // Poll every 2 seconds
  };

  const stopPolling = () => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }
  };

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>
  ) => {
    const { name, value, type } = e.target;
    const checked = (e.target as HTMLInputElement).checked;

    setFormData((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  const handleBrowse = () => {
    // Placeholder for export path browse functionality
    toast.info("Browse", "Directory browser not yet implemented");
  };

  const handleScan = async () => {
    // Validation
    if (!selectedFile) {
      toast.error("No file selected", "Please select a ZIP file to scan");
      return;
    }

    if (!formData.applicationName.trim()) {
      toast.error(
        "Application name required",
        "Please enter an application name"
      );
      return;
    }

    // Attack mode validation
    if (formData.attackMode) {
      if (!formData.targetIp.trim()) {
        toast.error(
          "IP address required",
          "Please enter a target IP address for attack mode"
        );
        return;
      }
      if (!formData.targetPort.trim()) {
        toast.error(
          "Port required",
          "Please enter a target port for attack mode"
        );
        return;
      }
      // Basic IP validation (optional but recommended)
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (!ipPattern.test(formData.targetIp.trim())) {
        toast.error(
          "Invalid IP address",
          "Please enter a valid IP address (e.g., 192.168.1.1)"
        );
        return;
      }
      // Basic port validation
      const port = parseInt(formData.targetPort.trim());
      if (isNaN(port) || port < 1 || port > 65535) {
        toast.error(
          "Invalid port",
          "Please enter a valid port number (1-65535)"
        );
        return;
      }
    }

    // Clear previous scan from storage
    clearScanFromStorage();

    setIsUploading(true);

    try {
      // Create FormData for file upload
      const uploadData = new FormData();
      uploadData.append("zipFile", selectedFile);
      uploadData.append("applicationName", formData.applicationName);
      uploadData.append("maxTokenLength", formData.maxTokenLength);
      uploadData.append("batchSize", formData.batchSize);
      uploadData.append("minConfidence", formData.minConfidence);
      uploadData.append("quickScan", formData.quickScan.toString());
      uploadData.append("demoMode", formData.demoMode.toString());
      uploadData.append("attackMode", formData.attackMode.toString());
      if (formData.attackMode) {
        uploadData.append("targetIp", formData.targetIp);
        uploadData.append("targetPort", formData.targetPort);
      }

      toast.success("Uploading...", "Processing your ZIP file");

      const response = await http.post("/scans/upload", uploadData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      if (response.data.success) {
        const scanId = response.data.scan_id;
        toast.success("Scan started", `Scan ID: ${scanId}`);

        setIsScanning(true);
        const initialProgress = {
          scan_id: scanId,
          status: response.data.status,
          project_name: formData.applicationName,
        };
        setScanProgress(initialProgress);

        // Save to localStorage
        saveScanToStorage(initialProgress);

        // Start polling for progress
        startPolling(scanId);
      }
    } catch (error: any) {
      console.error("Error starting scan:", error);
      toast.error(
        "Scan failed",
        error.response?.data?.message || error.message || "Failed to start scan"
      );
    } finally {
      setIsUploading(false);
    }
  };

  const handleStop = async () => {
    if (!scanProgress?.scan_id) {
      toast.warning("No active scan", "There is no scan to stop");
      return;
    }

    try {
      const response = await http.post(`/scans/${scanProgress.scan_id}/stop`);

      if (response.data.success) {
        toast.success("Scan stopped", "The scan has been cancelled");
        stopPolling();
        setIsScanning(false);
        setScanProgress((prev) =>
          prev ? { ...prev, status: "cancelled" } : null
        );
      }
    } catch (error: any) {
      console.error("Error stopping scan:", error);
      toast.error(
        "Stop failed",
        error.response?.data?.message || "Failed to stop scan"
      );
    }
  };

  const handleDismissScan = () => {
    clearScanFromStorage();
    setScanProgress(null);
    setIsScanning(false);
    toast.success("Scan dismissed", "Scan history cleared");
  };

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
        return "Pending";
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

  return (
    <div className="overflow-auto text-white">
      <div className="max-w-6xl mx-auto space-y-6 px-6">
        {/* Scan Progress Section */}
        {scanProgress && (
          <div className="glassmorphism-card rounded-xl p-8 border border-blue-500/20">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center space-x-3">
                <svg
                  className="w-5 h-5 text-blue-500 animate-spin"
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
                <h2 className="text-xl font-semibold text-white">
                  Scan Progress
                </h2>
              </div>
              <div className="flex items-center space-x-3">
                <span
                  className={`text-sm font-medium ${getStatusColor(
                    scanProgress.status
                  )}`}
                >
                  {getStageLabel(scanProgress.status)}
                </span>
                {/* Show dismiss button only for finished scans */}
                {["completed", "failed", "cancelled"].includes(
                  scanProgress.status
                ) && (
                  <button
                    onClick={handleDismissScan}
                    className="px-3 py-1 bg-gray-800/50 border border-gray-700/50 rounded-lg text-gray-400 hover:text-red-400 hover:border-red-500/50 transition-all text-sm flex items-center space-x-1"
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
                        d="M6 18L18 6M6 6l12 12"
                      />
                    </svg>
                    <span>Dismiss</span>
                  </button>
                )}
              </div>
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-black/30 rounded-lg p-4">
                  <p className="text-gray-400 text-sm mb-1">Scan ID</p>
                  <p className="text-white font-mono text-sm">
                    {scanProgress.scan_id}
                  </p>
                </div>
                <div className="bg-black/30 rounded-lg p-4">
                  <p className="text-gray-400 text-sm mb-1">Project</p>
                  <p className="text-white text-sm">
                    {scanProgress.project_name}
                  </p>
                </div>
              </div>

              {scanProgress.progress && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-black/30 rounded-lg p-4">
                    <p className="text-gray-400 text-sm mb-1">Files Scanned</p>
                    <p className="text-white text-2xl font-semibold">
                      {scanProgress.progress.files_scanned || 0}
                    </p>
                  </div>
                  <div className="bg-black/30 rounded-lg p-4">
                    <p className="text-gray-400 text-sm mb-1">
                      Vulnerabilities
                    </p>
                    <p className="text-red-400 text-2xl font-semibold">
                      {scanProgress.progress.vulnerabilities_found || 0}
                    </p>
                  </div>
                  <div className="bg-black/30 rounded-lg p-4">
                    <p className="text-gray-400 text-sm mb-1">
                      Exploits Generated
                    </p>
                    <p className="text-yellow-400 text-2xl font-semibold">
                      {scanProgress.progress.exploits_generated || 0}
                    </p>
                  </div>
                  <div className="bg-black/30 rounded-lg p-4">
                    <p className="text-gray-400 text-sm mb-1">Current Stage</p>
                    <p className="text-blue-400 text-2xl font-semibold">
                      {scanProgress.progress.current_stage || 0}/3
                    </p>
                  </div>
                </div>
              )}

              {scanProgress.progress?.current_file && (
                <div className="bg-black/30 rounded-lg p-4">
                  <p className="text-gray-400 text-sm mb-1">Current File</p>
                  <p className="text-white text-sm font-mono truncate">
                    {scanProgress.progress.current_file}
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Repository Section */}
        <div className="glassmorphism-card rounded-xl p-8 border border-red-500/20">
          <RepositoryCard
            selectedFile={selectedFile}
            formData={{
              applicationName: formData.applicationName,
              quickScan: formData.quickScan,
              demoMode: formData.demoMode,
              attackMode: formData.attackMode,
              targetIp: formData.targetIp,
              targetPort: formData.targetPort,
            }}
            isScanning={isScanning}
            isUploading={isUploading}
            onFileSelect={setSelectedFile}
            onInputChange={handleInputChange}
          />
        </div>

        {/* Export Settings Section */}
        <div className="glassmorphism-card rounded-xl p-8 border border-red-500/20">
          <ExportSettingsCard
            exportProjectPath={formData.exportProjectPath}
            exportFormat={formData.exportFormat}
            onInputChange={handleInputChange}
            onFormatChange={(value) =>
              setFormData((prev) => ({ ...prev, exportFormat: value }))
            }
            onBrowse={handleBrowse}
          />
        </div>

        {/* Action Buttons */}
        <div className="flex justify-center items-center space-x-6 pt-8">
          <button
            onClick={handleStop}
            disabled={!isScanning || isUploading}
            className="px-12 py-3 bg-gray-800/30 border border-gray-600/30 rounded-lg text-gray-400 hover:bg-gray-700/50 hover:border-gray-500/50 hover:text-gray-200 transition-all font-medium disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Stop
          </button>
          <button
            onClick={handleScan}
            disabled={isScanning || isUploading || !selectedFile}
            className="px-12 py-3 bg-red-600/20 border border-red-500/50 rounded-lg text-red-400 hover:bg-red-600/30 hover:border-red-500/70 hover:text-red-300 transition-all font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
          >
            {isUploading ? (
              <>
                <svg
                  className="w-4 h-4 animate-spin"
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
                <span>Uploading...</span>
              </>
            ) : (
              <span>Start Scan</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ScanPage;
