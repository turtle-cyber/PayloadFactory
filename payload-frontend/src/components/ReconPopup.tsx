import { Dialog, DialogContent } from "@/components/ui/dialog";
import CircularProgress from "@mui/material/CircularProgress";
import { X, AlertTriangle } from "lucide-react";

interface ReconPopupProps {
  isOpen: boolean;
  onClose: () => void;
  isScanning: boolean;
  scanFailed?: boolean;
  errorMessage?: string;
  onOk?: () => void;
}

const ReconPopup: React.FC<ReconPopupProps> = ({
  isOpen,
  onClose,
  isScanning,
  scanFailed = false,
  errorMessage,
  onOk,
}) => {
  const handleOk = () => {
    onOk?.();
    onClose();
  };

  // Determine the current state
  const isFailed = !isScanning && scanFailed;

  // Get title based on state
  const getTitle = () => {
    if (isScanning) return "Recon Underway....";
    if (isFailed) return "Recon Failed";
    return "Recon Completed";
  };

  // Get header background color based on state
  const getHeaderBg = () => {
    if (isFailed) return "bg-[#2C0C0C]";
    return "bg-[#260C0C]";
  };

  return (
    <Dialog open={isOpen}>
      <DialogContent
        className="border-[#353030] !rounded-2xl"
        onInteractOutside={(e) => e.preventDefault()}
        onEscapeKeyDown={(e) => e.preventDefault()}
      >
        {/* Header with title and spinner/icon */}
        <div>
          <div
            className={`${getHeaderBg()} text-[#949494] px-4 py-1 rounded-t-2xl flex align-center justify-between`}
          >
            <span>{getTitle()}</span>
            <div>
              {isScanning ? (
                <CircularProgress size="20px" thickness={6} color={"inherit"} />
              ) : isFailed ? (
                <AlertTriangle className="text-red-500 w-5 h-5" />
              ) : (
                <X
                  className="cursor-pointer hover:text-white transition-colors"
                  onClick={onClose}
                />
              )}
            </div>
          </div>
          <div className="bg-[#e5e5e51a] rounded-b-2xl p-2 h-32 flex flex-col items-center justify-around">
            <div className="text-sm text-[#795e5e] text-center px-4">
              {isScanning ? (
                <span>
                  Analyzing the target and establishing its footprint. Stand by
                  for intel
                </span>
              ) : isFailed ? (
                <span className="text-red-400">
                  {errorMessage ||
                    "Scan failed. Please check the target and try again."}
                </span>
              ) : (
                <span>
                  Target Analysis is done. The fingerprint table is now
                  populated.
                </span>
              )}
            </div>

            {isScanning ? (
              <div className="bg-[#6161611f] border border-[#353030] text-[#4b4b4b] py-1 px-6 rounded-lg text-sm">
                Scanning...
              </div>
            ) : isFailed ? (
              <button
                onClick={onClose}
                className="bg-[#ff11111f] border border-[#795a5a] rounded-lg text-sm px-6 py-1 text-[#795e5e] hover:bg-[#ff11113f] transition-colors cursor-pointer"
              >
                Close
              </button>
            ) : (
              <button
                onClick={handleOk}
                className="bg-[#ff11111f] border border-[#795a5a] rounded-lg text-sm px-6 py-1 text-[#795e5e] hover:bg-[#ff11113f] transition-colors cursor-pointer"
              >
                OK
              </button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default ReconPopup;
