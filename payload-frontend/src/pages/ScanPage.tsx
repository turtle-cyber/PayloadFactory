import { useState, useEffect, useRef } from "react";
import { toast } from "../utils/toast";
import { http } from "../utils/http";

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
  const fileInputRef = useRef<HTMLInputElement>(null);
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

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      // Validate file type
      if (!file.name.toLowerCase().endsWith(".zip")) {
        toast.error("Invalid file type", "Please select a ZIP file");
        return;
      }

      // Validate file size (max 100MB)
      const maxSize = 100 * 1024 * 1024;
      if (file.size > maxSize) {
        toast.error("File too large", "Maximum file size is 100MB");
        return;
      }

      setSelectedFile(file);
      toast.success("File selected", file.name);
    }
  };

  const handleBrowse = () => {
    fileInputRef.current?.click();
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
          <div className="flex items-center space-x-3 mb-6">
            <svg
              className="w-5 h-5 text-red-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"
              />
            </svg>
            <h2 className="text-xl font-semibold text-white">
              Upload Project (ZIP)
            </h2>
          </div>

          <div className="space-y-6">
            {/* Hidden file input */}
            <input
              ref={fileInputRef}
              type="file"
              accept=".zip"
              onChange={handleFileSelect}
              className="hidden"
            />

            {/* Project ZIP Upload */}
            <div>
              <label className="block text-sm text-gray-400 mb-3">
                Project ZIP File (Max 100MB)
              </label>
              <div className="flex items-center space-x-3">
                <input
                  type="text"
                  value={selectedFile?.name || ""}
                  placeholder="No file selected"
                  readOnly
                  className="flex-1 bg-black/50 border border-gray-700/50 rounded-lg px-4 py-3 text-white placeholder-gray-600 focus:outline-none cursor-not-allowed"
                />
                <button
                  onClick={handleBrowse}
                  disabled={isScanning || isUploading}
                  className="px-4 py-3 bg-gray-800/50 border border-gray-700/50 rounded-lg text-gray-300 hover:bg-gray-700/50 hover:text-white transition-all flex items-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
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
                      d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                    />
                  </svg>
                  <span>Browse</span>
                </button>
              </div>
              {selectedFile && (
                <p className="text-xs text-gray-500 mt-2">
                  Selected: {selectedFile.name} (
                  {(selectedFile.size / 1024 / 1024).toFixed(2)} MB)
                </p>
              )}
            </div>

            {/* Application Name */}
            <div>
              <label className="block text-sm text-gray-400 mb-3">
                Enter Application Name:
              </label>
              <input
                type="text"
                name="applicationName"
                value={formData.applicationName}
                onChange={handleInputChange}
                disabled={isScanning || isUploading}
                className="w-full max-w-md bg-black/50 border border-gray-700/50 rounded-lg px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              />
            </div>

            {/* Scan Options */}
            <div className="flex items-center space-x-6">
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  name="quickScan"
                  checked={formData.quickScan}
                  onChange={handleInputChange}
                  disabled={isScanning || isUploading}
                  className="w-4 h-4 bg-black/50 border border-gray-700/50 rounded text-blue-500 focus:ring-blue-500 disabled:opacity-50"
                />
                <span className="text-sm text-gray-300">Quick Scan</span>
              </label>

              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  name="demoMode"
                  checked={formData.demoMode}
                  onChange={handleInputChange}
                  disabled={isScanning || isUploading}
                  className="w-4 h-4 bg-black/50 border border-gray-700/50 rounded text-blue-500 focus:ring-blue-500 disabled:opacity-50"
                />
                <span className="text-sm text-gray-300">Demo Mode</span>
              </label>

              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  name="attackMode"
                  checked={formData.attackMode}
                  onChange={handleInputChange}
                  disabled={isScanning || isUploading}
                  className="w-4 h-4 bg-black/50 border border-gray-700/50 rounded text-red-500 focus:ring-red-500 disabled:opacity-50"
                />
                <span className="text-sm text-gray-300">
                  Enable Attack Mode (Stage 3)
                </span>
                <span className="text-sm text-gray-400">Target IP:</span>
                <input
                  type="text"
                  name="targetIp"
                  value={formData.targetIp}
                  onChange={handleInputChange}
                  placeholder="192.168.x.x"
                  disabled={!formData.attackMode || isScanning || isUploading}
                  className="w-40 bg-black/50 border border-gray-700/50 rounded-lg px-3 py-1 text-white placeholder-gray-600 focus:outline-none focus:border-red-500/50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                />
                <span className="text-sm text-gray-400">Port:</span>
                <input
                  type="text"
                  name="targetPort"
                  value={formData.targetPort}
                  onChange={handleInputChange}
                  placeholder="80"
                  disabled={!formData.attackMode || isScanning || isUploading}
                  className="w-24 bg-black/50 border border-gray-700/50 rounded-lg px-3 py-1 text-white placeholder-gray-600 focus:outline-none focus:border-red-500/50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                />
              </label>
            </div>
          </div>
        </div>

        {/* Scan Configuration Section */}
        {/* <div className="glassmorphism-card rounded-xl p-8 border border-red-500/20">
          <div className="flex items-center space-x-3 mb-6">
            <svg
              className="w-5 h-5 text-red-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
              />
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
              />
            </svg>
            <h2 className="text-xl font-semibold text-white">
              Scan Configuration
            </h2>
          </div>

          <div className="space-y-6">
            <div>
              <label className="block text-sm text-gray-400 mb-3">
                Max Token Length
              </label>
              <div className="relative">
                <select
                  name="maxTokenLength"
                  value={formData.maxTokenLength}
                  onChange={handleInputChange}
                  className="w-full max-w-md bg-black/50 border border-gray-700/50 rounded-lg px-4 py-3 text-white appearance-none focus:outline-none focus:border-red-500/50 transition-colors cursor-pointer"
                >
                  <option value="128">128</option>
                  <option value="256">256</option>
                  <option value="512">512</option>
                  <option value="1024">1024</option>
                  <option value="2048">2048</option>
                </select>
                <div className="absolute right-4 top-1/2 transform -translate-y-1/2 pointer-events-none">
                  <svg
                    className="w-4 h-4 text-gray-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                </div>
              </div>
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-3">
                Batch Size
              </label>
              <div className="relative">
                <select
                  name="batchSize"
                  value={formData.batchSize}
                  onChange={handleInputChange}
                  className="w-full max-w-md bg-black/50 border border-gray-700/50 rounded-lg px-4 py-3 text-white appearance-none focus:outline-none focus:border-red-500/50 transition-colors cursor-pointer"
                >
                  <option value="8">8</option>
                  <option value="16">16</option>
                  <option value="32">32</option>
                  <option value="64">64</option>
                  <option value="128">128</option>
                </select>
                <div className="absolute right-4 top-1/2 transform -translate-y-1/2 pointer-events-none">
                  <svg
                    className="w-4 h-4 text-gray-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                </div>
              </div>
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-3">
                Min Confidence (0.0 - 1.0)
              </label>
              <div className="relative">
                <select
                  name="minConfidence"
                  value={formData.minConfidence}
                  onChange={handleInputChange}
                  className="w-full max-w-md bg-black/50 border border-gray-700/50 rounded-lg px-4 py-3 text-white appearance-none focus:outline-none focus:border-red-500/50 transition-colors cursor-pointer"
                >
                  <option value="0.1">0.1</option>
                  <option value="0.2">0.2</option>
                  <option value="0.3">0.3</option>
                  <option value="0.4">0.4</option>
                  <option value="0.5">0.5</option>
                  <option value="0.6">0.6</option>
                  <option value="0.7">0.7</option>
                  <option value="0.8">0.8</option>
                  <option value="0.9">0.9</option>
                  <option value="1.0">1.0</option>
                </select>
                <div className="absolute right-4 top-1/2 transform -translate-y-1/2 pointer-events-none">
                  <svg
                    className="w-4 h-4 text-gray-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                </div>
              </div>
            </div>
          </div>
        </div> */}

        {/* Export Settings Section */}
        <div className="glassmorphism-card rounded-xl p-8 border border-red-500/20">
          <div className="flex items-center space-x-3 mb-6">
            <svg
              className="w-5 h-5 text-red-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"
              />
            </svg>
            <h2 className="text-xl font-semibold text-white">
              Export Settings
            </h2>
          </div>

          <div className="space-y-6">
            {/* Export Project Path */}
            <div>
              <label className="block text-sm text-gray-400 mb-3">
                Project Path
              </label>
              <div className="flex items-center space-x-3">
                <input
                  type="text"
                  name="exportProjectPath"
                  value={formData.exportProjectPath}
                  onChange={handleInputChange}
                  placeholder="Enter Output File Path"
                  className="flex-1 bg-black/50 border border-gray-700/50 rounded-lg px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-red-500/50 transition-colors"
                />
                <button
                  onClick={() => handleBrowse()}
                  className="px-4 py-3 bg-gray-800/50 border border-gray-700/50 rounded-lg text-gray-300 hover:bg-gray-700/50 hover:text-white transition-all flex items-center space-x-2"
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
                      d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"
                    />
                  </svg>
                  <span>Browse</span>
                </button>
              </div>
            </div>

            {/* Export Format */}
            <div>
              <label className="block text-sm text-gray-400 mb-3">
                Export Format:
              </label>
              <div className="relative">
                <select
                  name="exportFormat"
                  value={formData.exportFormat}
                  onChange={handleInputChange}
                  className="w-full max-w-md bg-black/50 border border-gray-700/50 rounded-lg px-4 py-3 text-white appearance-none focus:outline-none focus:border-cyan-500/50 transition-colors cursor-pointer"
                >
                  <option value="Excel.xlsx">Excel.xlsx</option>
                  <option value="CSV.csv">CSV.csv</option>
                  <option value="JSON.json">JSON.json</option>
                  <option value="PDF.pdf">PDF.pdf</option>
                </select>
                <div className="absolute right-4 top-1/2 transform -translate-y-1/2 pointer-events-none">
                  <svg
                    className="w-4 h-4 text-gray-400"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                </div>
              </div>
            </div>
          </div>
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
