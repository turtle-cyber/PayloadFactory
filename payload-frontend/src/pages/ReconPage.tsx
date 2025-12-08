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
  const [ports, setPorts] = useState("");
  const [appName, setAppName] = useState("");
  const [services, setServices] = useState<any[]>([]);
  const [analysis, setAnalysis] = useState("");
  const [mode, setMode] = useState<"whitebox" | "blackbox">("whitebox");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [selectedServiceIndex, setSelectedServiceIndex] = useState<number | null>(null);
  const [serviceAnalyses, setServiceAnalyses] = useState<any[]>([]);
  const [acknowledgmentChecked, setAcknowledgmentChecked] = useState(false);

  // Service selection handler
  const handleServiceSelect = (index: number) => {
    console.log("=== Service Selection Debug ===");
    console.log("Selected index:", index);
    console.log("Total service analyses:", serviceAnalyses.length);
    console.log("Service analyses array:", serviceAnalyses);
    console.log("Analysis at selected index:", serviceAnalyses[index]);

    setSelectedServiceIndex(index);
    if (serviceAnalyses[index]) {
      const analysisData = serviceAnalyses[index];

      // Try different possible fields for the LLM analysis
      let exploitSteps = "";

      if (typeof analysisData.exploitation_steps === 'string') {
        exploitSteps = analysisData.exploitation_steps;
      } else if (Array.isArray(analysisData.exploitation_steps)) {
        exploitSteps = analysisData.exploitation_steps.join('\n');
      } else if (analysisData.llm_analysis) {
        exploitSteps = analysisData.llm_analysis;
      } else if (analysisData.analysis) {
        exploitSteps = analysisData.analysis;
      } else if (analysisData.raw_output) {
        exploitSteps = analysisData.raw_output;
      } else {
        // Fallback: show the entire object
        exploitSteps = JSON.stringify(analysisData, null, 2);
      }

      console.log("Exploit steps to display:", exploitSteps);
      setAnalysis(exploitSteps);
    } else {
      console.log("No analysis found at this index");
    }
    setAcknowledgmentChecked(false);
  };

  // Acknowledgment handler
  const handleAcknowledgmentChange = (checked: boolean) => {
    setAcknowledgmentChecked(checked);
  };

  // Scan handler
  const handleScan = async () => {
    if (!targetIp.trim()) {
      toast.error("Target IP required", "Please enter a target IP address");
      return;
    }

    setIsScanning(true);
    try {
      const response = await http.post("/recon/scan", {
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
          const analysisResponse = await http.post("/recon/analyze", {
            services: response.data.data.services,
            model: "hermes",
          });

          if (analysisResponse.data.success) {
            console.log("=== Auto-Analyze Debug ===");
            console.log("Analysis response:", analysisResponse.data.data.analysis);
            console.log("Number of analyses:", analysisResponse.data.data.analysis.length);
            setServiceAnalyses(analysisResponse.data.data.analysis);
            setAnalysis("");
            setSelectedServiceIndex(null);
            setAcknowledgmentChecked(false);
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
      const response = await http.post("/recon/blackbox", {
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
      // Whitebox mode enables attack and auto-execution by default
      const uploadData = new FormData();
      uploadData.append("zipFile", selectedFile);
      uploadData.append("targetIp", targetIp);
      uploadData.append("targetPort", ports.split(",")[0] || "8080");
      uploadData.append("applicationName", appName || "Whitebox Target");
      // Enable attack mode and auto-execution by default for whitebox
      uploadData.append("attackMode", "true");
      uploadData.append("autoExec", "true");
      uploadData.append("demoMode", "false");

      const response = await http.post("/recon/whitebox/upload", uploadData, {
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
            <FingerprintTable
              services={services}
              selectedServiceIndex={selectedServiceIndex}
              onServiceSelect={handleServiceSelect}
            />
          </div>

          {/*Guide Card */}
          <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
            <GuideCard
              analysis={analysis}
              acknowledgmentChecked={acknowledgmentChecked}
              onAcknowledgmentChange={handleAcknowledgmentChange}
            />
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
              disabled={!acknowledgmentChecked}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReconPage;
