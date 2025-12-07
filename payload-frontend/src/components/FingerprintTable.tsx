interface Service {
  port: number;
  state: string;
  service: string;
  product: string;
  version: string;
  banner?: string;
}

interface FingerprintTableProps {
  services: Service[];
  selectedServiceIndex: number | null;
  onServiceSelect: (index: number) => void;
}

const FingerprintTable: React.FC<FingerprintTableProps> = ({
  services,
  selectedServiceIndex,
  onServiceSelect
}) => {
  return (
    <>
      <div className="py-2 px-4 rounded-lg bg-[#2f2f2f]">
        <span>Fingerprints</span>
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
              <th className="text-center p-4 text-sm font-semibold text-gray-400">
              </th>
            </tr>
          </thead>
          <tbody>
            {services.length === 0 ? (
              <tr>
                <td
                  colSpan={5}
                  className="text-center p-8 text-gray-500 text-sm"
                >
                  No services found. Run a scan to discover services.
                </td>
              </tr>
            ) : (
              services.map((service, index) => (
                <tr
                  key={index}
                  className={`border-b border-gray-800 hover:bg-gray-800/30 transition-colors ${
                    selectedServiceIndex === index ? 'bg-blue-500/10' : ''
                  }`}
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
                    {service.version && service.version !== "unknown" ? service.version : "Unclassified"}
                  </td>
                  <td className="p-4 text-center">
                    <div className="flex items-center justify-center">
                      <input
                        type="radio"
                        name="service-selection"
                        checked={selectedServiceIndex === index}
                        onChange={() => onServiceSelect(index)}
                        className="w-5 h-5 cursor-pointer accent-blue-500"
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
