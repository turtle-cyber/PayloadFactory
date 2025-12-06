import { useState } from "react";
import { useNavigate } from "react-router-dom";
import ExploitGenerationCard from "@/components/ExploitGenerationCard";
import FingerprintTable from "@/components/FingerprintTable";
import GuideCard from "@/components/GuideCard";
import ReconTargetCard from "@/components/ReconTargetCard";
import { http } from "@/utils/http";
import { toast } from "@/utils/toast";

const ReconPage = () => {
  const navigate = useNavigate();

  // State management
  const [targetIp, setTargetIp] = useState("");
  const [ports, setPorts] = useState("21,22,80,443,3306,8080");
  const [appName, setAppName] = useState("");
  const [services, setServices] = useState<any[]>([]);
  const [analysis, setAnalysis] = useState("");
  const [mode, setMode] = useState<"whitebox" | "blackbox">("whitebox");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Scan handler
  const handleScan = async () => {
    if (!targetIp.trim()) {
      toast.error("Target IP required", "Please enter a target IP address");
      return;
    }

    setIsScanning(true);
    try {
      const response = await http.post("/api/recon/scan", {
        target_ip: targetIp,
        ports: ports,
        application_name: appName || "Unknown Target",
      });

      if (response.data.success) {
        setServices(response.data.data.services);
        toast.success(
          "Scan complete",
          `Found ${response.data.data.services.length} services`
        );

        // Auto-analyze
        if (response.data.data.services.length > 0) {
          const analysisResponse = await http.post("/api/recon/analyze", {
            services: response.data.data.services,
            model: "hermes",
          });

          if (analysisResponse.data.success) {
            setAnalysis(
              analysisResponse.data.data.analysis
                .map((a: any) => a.exploitation_steps)
                .join("\n\n")
            );
          }
        }
      }
    } catch (error: any) {
      toast.error("Scan failed", error.response?.data?.message || error.message);
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
      const response = await http.post("/api/recon/blackbox", {
        target_ip: targetIp,
        ports: ports,
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

  // Whitebox handler
  const handleWhitebox = async () => {
    if (!selectedFile) {
      toast.error("ZIP file required", "Please select a source code ZIP file");
      return;
    }

    if (!targetIp.trim()) {
      toast.error("Target IP required", "Please enter a target IP address");
      return;
    }

    setIsAnalyzing(true);
    try {
      // Create FormData for file upload
      const uploadData = new FormData();
      uploadData.append("zipFile", selectedFile);
      uploadData.append("targetIp", targetIp);
      uploadData.append("targetPort", ports.split(",")[0]);
      uploadData.append("applicationName", appName || "Whitebox Target");

      const response = await http.post("/api/recon/whitebox/upload", uploadData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      if (response.data.success) {
        toast.success("Whitebox scan initiated", "Navigating to scan page...");
        // Navigate to scan page
        navigate("/scan", { state: { scanId: response.data.data.scan_id } });
      }
    } catch (error: any) {
      toast.error(
        "Whitebox workflow failed",
        error.response?.data?.message || error.message
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div>
      <div className="overflow-auto text-white pb-6">
        <div className="max-w-6xl mx-auto px-6 space-y-6">
          <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
            <ReconTargetCard
              targetIp={targetIp}
              setTargetIp={setTargetIp}
              ports={ports}
              setPorts={setPorts}
              appName={appName}
              setAppName={setAppName}
              onScan={handleScan}
              isScanning={isScanning}
            />
          </div>

          {/*Fingerprints Table */}
          <div>
            <FingerprintTable services={services} />
          </div>

          {/*Guide Card */}
          <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
            <GuideCard analysis={analysis} />
          </div>

          {/*Exploit Generation Window */}
          <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
            <ExploitGenerationCard
              mode={mode}
              setMode={setMode}
              selectedFile={selectedFile}
              onFileSelect={setSelectedFile}
              onGenerate={mode === "whitebox" ? handleWhitebox : handleBlackbox}
              isGenerating={isAnalyzing}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReconPage;
