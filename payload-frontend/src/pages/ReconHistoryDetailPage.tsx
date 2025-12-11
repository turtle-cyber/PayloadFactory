import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { http } from "@/utils/http";
import { GET_RECON_BY_ID } from "@/endpoints/recon.endpoints";
import { toast } from "sonner";
import { ArrowLeft, ArrowRight } from "lucide-react";

interface OsInfo {
  name: string;
  accuracy: number;
  family: string;
  vendor: string;
  os_gen: string;
}

interface Service {
  port: number;
  protocol: string;
  service: string;
  version: string;
  product: string;
  banner: string;
  aiml_analysis?: string;
}

interface ReconDetail {
  scan_id: string;
  scan_name: string;
  target_ip: string;
  status: string;
  mode: string;
  exec_time: string;
  date: string;
  os_info: OsInfo | null;
  services: Service[];
}

const formatStatus = (status: string | undefined | null) => {
  if (!status) {
    return "bg-gray-500/20 text-gray-400 p-2 rounded-md";
  }
  const formattedStatus = status.toLowerCase();
  if (formattedStatus === "completed") {
    return "bg-green-500/20 text-green-400 p-2 rounded-md";
  } else if (formattedStatus === "failed") {
    return "bg-red-500/20 text-red-400 p-2 rounded-md";
  } else if (formattedStatus === "in_progress") {
    return "bg-blue-500/20 text-blue-400 p-2 rounded-md";
  } else {
    return "bg-gray-500/20 text-gray-400 p-2 rounded-md";
  }
};

const ReconHistoryDetailPage = () => {
  const { recon_id } = useParams<{ recon_id: string }>();
  const navigate = useNavigate();
  const [recon, setRecon] = useState<ReconDetail | null>(null);
  const [loading, setLoading] = useState(true);

  const handleServiceArrowClick = (serviceIndex: number) => {
    if (!recon) return;

    const selectedService = recon.services[serviceIndex];

    // Navigate to ReconPage with prefilled data
    navigate("/recon", {
      state: {
        fromHistory: true,
        target_ip: recon.target_ip,
        scan_name: recon.scan_name,
        os_info: recon.os_info,
        services: recon.services,
        selectedServiceIndex: serviceIndex,
        selectedServiceAnalysis: selectedService.aiml_analysis || null,
      },
    });
  };

  useEffect(() => {
    const fetchReconDetail = async () => {
      if (!recon_id) return;

      setLoading(true);
      try {
        const response = await http.get(GET_RECON_BY_ID(recon_id));
        if (response?.data?.success) {
          setRecon(response.data.recon);
        } else {
          toast.error("Recon not found");
          navigate("/recon/history");
        }
      } catch (error) {
        console.error("Error fetching recon detail:", error);
        toast.error("Failed to fetch recon details");
      } finally {
        setLoading(false);
      }
    };

    fetchReconDetail();
  }, [recon_id, navigate]);

  if (loading) {
    return (
      <div className="overflow-auto text-white">
        <div className="max-w-6xl mx-auto space-y-6 px-6">
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500 mx-auto mb-4"></div>
              <p className="text-gray-400">Loading recon details...</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!recon) {
    return (
      <div className="overflow-auto text-white">
        <div className="max-w-6xl mx-auto space-y-6 px-6">
          <div className="flex items-center justify-center py-20">
            <p className="text-gray-400">Recon not found</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="overflow-auto text-white">
      <div className="max-w-6xl mx-auto space-y-6 px-6">
        {/* Header */}
        <div className="glassmorphism-card border border-red-600/20 py-2 px-4 rounded-lg flex items-center gap-4">
          <button
            onClick={() => navigate("/recon/history")}
            className="p-2 rounded-lg hover:bg-gray-700 transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div className="flex-1">
            <h1 className="text-lg">{recon.scan_name}</h1>
            <p className="text-sm text-gray-400">{recon.target_ip}</p>
          </div>
          <span className={formatStatus(recon.status)}>
            {recon.status.charAt(0).toUpperCase() + recon.status.slice(1)}
          </span>
        </div>

        {/* Info Cards */}
        <div className="grid grid-cols-3 md:grid-cols-3 gap-3">
          {/* <div className="bg-[#1a1714] p-4 rounded-lg">
            <p className="text-sm text-gray-400">Mode</p>
            <p className="text-lg font-medium">{recon.mode || "-"}</p>
          </div> */}
          <div className="glassmorphism-card border border-red-600/20 p-4 rounded-lg">
            <p className="text-sm text-gray-400">Execution Time</p>
            <p className="text-md font-medium">{recon.exec_time || "-"}</p>
          </div>
          <div className="glassmorphism-card border border-red-600/20 p-4 rounded-lg">
            <p className="text-sm text-gray-400">Date</p>
            <p className="text-md font-medium">{recon.date || "-"}</p>
          </div>
          <div className="glassmorphism-card border border-red-600/20 p-4 rounded-lg">
            <p className="text-sm text-gray-400">OS Detected</p>
            <p className="text-md font-medium">{recon.os_info?.name || "-"}</p>
          </div>
        </div>

        {/* Services Table */}
        <div className="glassmorphism-card p-4 rounded-lg border border-red-500/20 max-h-[70vh] overflow-auto">
          <h2 className="text-lg font-semibold mb-4">
            Services ({recon.services.length})
          </h2>
          {recon.services.length === 0 ? (
            <p className="text-gray-400 text-center py-8">No services found</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left p-4 text-sm text-gray-400">
                      Port
                    </th>
                    <th className="text-left p-4 text-sm text-gray-400">
                      Protocol
                    </th>
                    <th className="text-left p-4 text-sm text-gray-400">
                      Service
                    </th>
                    <th className="text-left p-4 text-sm text-gray-400">
                      Product
                    </th>
                    <th className="text-left p-4 text-sm text-gray-400">
                      Version
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {recon.services.map((service, index) => (
                    <tr
                      key={index}
                      className="border-b border-gray-800 hover:bg-gray-900/50 transition-colors"
                    >
                      <td className="p-4 text-sm">{service.port}</td>
                      <td className="p-4 text-sm">{service.protocol}</td>
                      <td className="p-4 text-sm">{service.service}</td>
                      <td className="p-4 text-sm">{service.product || "-"}</td>
                      <td className="p-4 text-sm">{service.version || "-"}</td>
                      <td className="p-4">
                        <div
                          onClick={() => handleServiceArrowClick(index)}
                          className="flex p-1 w-10 align-center justify-center rounded-md border border-[#4b4b4b] text-[#4b4b4b] hover:border-red-500 hover:text-red-500 transition-colors"
                        >
                          <ArrowRight className="w-5 h-5 " />
                        </div>
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
  );
};

export default ReconHistoryDetailPage;
