import React from "react";
import { useNavigate } from "react-router-dom";

interface ReconHistoryItem {
  scan_id: string;
  scan_name: string;
  ip: string;
  status: string;
  exec_time: string;
  date: string;
}

interface ReconHistoryTableProps {
  data: ReconHistoryItem[];
  loading: boolean;
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

const ReconHistoryTable: React.FC<ReconHistoryTableProps> = ({
  data,
  loading,
}) => {
  const navigate = useNavigate();

  const handleRowClick = (scanId: string) => {
    navigate(`/recon/history/${scanId}`);
  };

  return (
    <>
      <div className="py-2 px-4 rounded-lg bg-[#2f2f2f] flex items-center justify-between">
        <span>Recon History</span>
      </div>

      <div className="bg-[#1a1714] p-4 mt-2 h-[50vh] overflow-auto rounded-lg">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500 mx-auto mb-4"></div>
              <p className="text-gray-400">Loading history...</p>
            </div>
          </div>
        ) : data.length === 0 ? (
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <p className="text-gray-400 text-lg mb-2">No history available</p>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left p-4 text-sm font-semibold text-gray-400">
                    Name
                  </th>
                  <th className="text-left p-4 text-sm font-semibold text-gray-400">
                    IP
                  </th>
                  <th className="text-left p-4 text-sm font-semibold text-gray-400">
                    Status
                  </th>
                  <th className="text-left p-4 text-sm font-semibold text-gray-400">
                    Execution Time
                  </th>
                  <th className="text-left p-4 text-sm font-semibold text-gray-400">
                    Date
                  </th>
                </tr>
              </thead>

              <tbody>
                {data.map((item) => (
                  <tr
                    key={item.scan_id}
                    onClick={() => handleRowClick(item.scan_id)}
                    className="cursor-pointer border-b border-gray-800 hover:bg-gray-900/50 transition-colors"
                  >
                    <td className="p-4">{item.scan_name}</td>
                    <td className="p-4">{item.ip}</td>
                    <td className="p-4">
                      <span className={formatStatus(item.status)}>
                        {item.status.charAt(0).toUpperCase() +
                          item.status.slice(1) || "Unknown"}
                      </span>
                    </td>
                    <td className="p-4">{item.exec_time || "-"}</td>
                    <td className="p-4">{item.date}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
};

export default ReconHistoryTable;
