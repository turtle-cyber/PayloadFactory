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
  selectedIndices: number[];
  onServiceToggle: (index: number) => void;
}

const FingerprintTable: React.FC<FingerprintTableProps> = ({
  services,
  osInfo,
  selectedIndices,
  onServiceToggle
}) => {
  // Format OS display string (e.g., "Linux 5.15" or "Windows 10")
  const osDisplay = osInfo && osInfo.name !== "Unknown" 
    ? `${osInfo.family !== "Unknown" ? osInfo.family : osInfo.name}${osInfo.os_gen !== "Unknown" ? ' ' + osInfo.os_gen : ''}`
    : "—";

  return (
    <>
      <div className="py-2 px-4 rounded-lg bg-[#2f2f2f] flex items-center justify-between">
        <span>Fingerprints</span>
        {selectedIndices.length > 0 && (
          <span className="text-sm text-blue-400">
            {selectedIndices.length} port{selectedIndices.length > 1 ? 's' : ''} selected
          </span>
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
                SERVICE
              </th>
              <th className="text-left p-4 text-sm font-semibold text-gray-400">
                VERSION
              </th>
              <th className="text-left p-4 text-sm font-semibold text-gray-400">
                OS
              </th>
              <th className="text-center p-4 text-sm font-semibold text-gray-400">
                SELECT
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
              services.map((service, index) => (
                <tr
                  key={index}
                  className={`border-b border-gray-800 hover:bg-gray-800/30 transition-colors cursor-pointer ${
                    selectedIndices.includes(index) ? 'bg-blue-500/10' : ''
                  }`}
                  onClick={() => onServiceToggle(index)}
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
                    {service.product || service.service || "unknown"}
                  </td>
                  <td className="p-4 text-sm text-gray-400 font-mono">
                    {service.version && service.version !== "unknown" ? service.version : "—"}
                  </td>
                  <td className="p-4 text-sm text-purple-400">
                    {osDisplay}
                  </td>
                  <td className="p-4 text-center">
                    <div className="flex items-center justify-center">
                      <input
                        type="checkbox"
                        checked={selectedIndices.includes(index)}
                        onChange={() => onServiceToggle(index)}
                        onClick={(e) => e.stopPropagation()}
                        className="w-5 h-5 cursor-pointer accent-blue-500 rounded"
                      />
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </>
  );
};

export default FingerprintTable;
