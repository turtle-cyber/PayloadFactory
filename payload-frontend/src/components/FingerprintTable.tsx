import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Info } from "lucide-react";
import React from "react";

interface Service {
  port: number;
  state: string;
  service: string;
  product: string;
  version: string;
  banner?: string;
}

interface OSInfo {
  name: string;
  accuracy: number;
  family: string;
  vendor: string;
  os_gen: string;
}

interface FingerprintTableProps {
  services: Service[];
  osInfo?: OSInfo | null;
  // Single selected index (or null for none)
  selectedIndex: number | null;
  // Select a service (or pass null to clear selection)
  onServiceSelect: (index: number | null) => void;
}

const FingerprintTable: React.FC<FingerprintTableProps> = ({
  services,
  osInfo,
  selectedIndex,
  onServiceSelect,
}) => {
  // Format OS display string (e.g., "Linux 5.15" or "Windows 10")
  const osDisplay =
    osInfo && osInfo.name !== "Unknown"
      ? `${osInfo.family !== "Unknown" ? osInfo.family : osInfo.name}${
          osInfo.os_gen !== "Unknown" ? " " + osInfo.os_gen : ""
        }`
      : "—";

  const handleRowClick = (index: number) => {
    // If clicked row is already selected, deselect it; otherwise select it
    if (selectedIndex === index) {
      onServiceSelect(null);
    } else {
      onServiceSelect(index);
    }
  };

  return (
    <>
      <div className="py-2 px-4 rounded-lg bg-[#2f2f2f] flex items-center justify-between">
        <span className="font-mono">Target Fingerprints</span>
        {selectedIndex !== null && selectedIndex !== undefined && (
          <span className="text-sm text-blue-400">1 port selected</span>
        )}
      </div>

      <div className="bg-[#1a1714] p-4 mt-2 h-[30vh] overflow-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left p-4 text-sm font-semibold text-gray-400">
                PORT
              </th>
              <th className="text-left p-4 text-sm font-semibold text-gray-400">
                STATE
              </th>
              <th className="text-left p-4 text-sm font-semibold text-gray-400">
                PRODUCT
              </th>
              <th className="text-left p-4 text-sm font-semibold text-gray-400">
                PROTOCOL
              </th>
              <th className="text-left p-4 text-sm font-semibold text-gray-400">
                VERSION
              </th>
              <th className="text-left p-4 text-sm font-semibold text-gray-400">
                OS
              </th>
              <th className="text-center justify-items-center p-4 text-sm font-semibold text-gray-400">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Info className="w-4 h-4 cursor-help" />
                    </TooltipTrigger>
                    <TooltipContent side="top">
                      Select one port at a time for Help Guide & Exploit
                      Generation
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </th>
            </tr>
          </thead>
          <tbody>
            {services.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="text-center p-8 text-gray-500 text-sm"
                >
                  No services found. Run a scan to discover services.
                </td>
              </tr>
            ) : (
              services.map((service, index) => {
                const isSelected = selectedIndex === index;
                return (
                  <tr
                    key={index}
                    className={`border-b border-gray-800 hover:bg-gray-800/30 transition-colors cursor-pointer ${
                      isSelected ? "bg-blue-500/10" : ""
                    }`}
                    onClick={() => handleRowClick(index)}
                  >
                    <td className="p-4 text-sm text-blue-400 font-mono">
                      {service.port}
                    </td>
                    <td className="p-4 text-sm">
                      <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs font-semibold">
                        {service.state || "open"}
                      </span>
                    </td>
                    <td className="p-4 text-sm text-gray-300">
                      {service.product || "Unclassified"}
                    </td>
                    <td className="p-4 text-sm text-gray-300">
                      {service.service || "Unclassified"}
                    </td>
                    <td className="p-4 text-sm text-gray-400 font-mono">
                      {service.version && service.version !== "Unclassified"
                        ? service.version
                        : "—"}
                    </td>
                    <td className="p-4 text-sm text-purple-400">{osDisplay}</td>
                    <td className="p-4 text-center">
                      <div className="flex items-center justify-center">
                        <input
                          type="radio"
                          name="fingerprint-selection"
                          aria-label={`Select service ${service.port}`}
                          checked={isSelected}
                          onChange={() => {
                            // radio onChange should mirror row click behaviour
                            handleRowClick(index);
                          }}
                          onClick={(e) => e.stopPropagation()}
                          className="w-5 h-5 cursor-pointer accent-blue-500 rounded-full"
                        />
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </>
  );
};

export default FingerprintTable;
