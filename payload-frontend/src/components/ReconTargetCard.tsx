import { ArrowRight, Crosshair, History } from "lucide-react";
import { useNavigate } from "react-router-dom";

interface ReconTargetCardProps {
  targetIp: string;
  setTargetIp: (value: string) => void;
  appName: string;
  setAppName: (value: string) => void;
  onScan: () => void;
  isScanning: boolean;
}

const ReconTargetCard: React.FC<ReconTargetCardProps> = ({
  targetIp,
  setTargetIp,
  appName,
  setAppName,
  onScan,
  isScanning,
}) => {
  const navigate = useNavigate();

  const handleNavigateHistory = () => {
    navigate("/recon/history");
  };

  return (
    <div>
      {/*Heading*/}
      <div className="items-center justify-between flex gap-2">
        <div className="text-gray-400 flex items-center gap-2">
          <Crosshair className="w-5" />
          <h2 className="text-blue-500 text-lg">Recon Target</h2>
        </div>

        <div
          className="p-2.5 h-11 w-11 justify-center items-center flex rounded-xl border border-gray-700/50 bg-transparent hover:border-gray-600 hover:bg-gray-800/80 transition-all shadow-lg cursor-pointer"
          onClick={handleNavigateHistory}
        >
          <History className="w-5 h-5 text-gray-400" />
        </div>
      </div>

      {/*Terminal Window */}
      <div className="p-4 ml-10">
        <div className="items-center justify-between flex rounded-t-lg bg-[#2f2f2f] py-3 px-4">
          <span className="font-md text-gray-500">Enter the Target's IP</span>
        </div>

        <div className="border-[#2f2f2f] border items-center bg-[#0d0d0d] p-4 rounded-b-lg">
          <div className="border border-[#2f2f2f] rounded-lg p-3">
            <div className="w-full focus:outline-none flex">
              <input
                type="text"
                name="targetIp"
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
                placeholder="IP / URL / DOMAIN"
                disabled={isScanning}
                className="w-full bg-transparent text-md text-blue-300 placeholder-blue-300/50 focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed"
              />
              <button
                onClick={onScan}
                disabled={isScanning}
                className="rounded-md border border-[#4b4b4b] text-[#4b4b4b] hover:border-red-500 hover:text-red-500 px-1 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isScanning ? (
                  <svg
                    className="w-5 h-5 animate-spin"
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
                ) : (
                  <ArrowRight className="w-5" />
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/*Inputs And Options*/}
      <div className="flex items-center ml-24 gap-x-4 mt-4">
        <span className="text-blue-300">Enter Name:</span>

        <input
          type="text"
          name="applicationName"
          value={appName}
          onChange={(e) => setAppName(e.target.value)}
          disabled={isScanning}
          className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm disabled:opacity-30 disabled:cursor-not-allowed"
          placeholder="My App"
        />
      </div>
    </div>
  );
};

export default ReconTargetCard;
