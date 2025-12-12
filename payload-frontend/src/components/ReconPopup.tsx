import { Dialog, DialogContent, DialogFooter } from "@/components/ui/dialog";
import CircularProgress from "@mui/material/CircularProgress";
import { X } from "lucide-react";

interface ReconPopupProps {
  isOpen: boolean;
  onClose: () => void;
  isScanning: boolean;
  onOk?: () => void;
}

const ReconPopup: React.FC<ReconPopupProps> = ({
  isOpen,
  onClose,
  isScanning,
  onOk,
}) => {
  const handleOk = () => {
    onOk?.();
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="border-[#353030] !rounded-2xl">
        {/* Header with title and spinner */}
        <div>
          <div className="bg-[#260C0C] text-[#949494] px-4 py-1 rounded-t-2xl flex align-center justify-between">
            <span>Reconnaissance In Progress....</span>
            <div>
              {isScanning ? (
                <CircularProgress
                  size="20px"
                  thickness={6}
                  color={"inherit"}
                />
              ) : (
                <X className="cursor-pointer hover:text-white transition-colors" onClick={onClose} />
              )}
            </div>
          </div>
          <div className="bg-[#e5e5e51a] rounded-b-2xl p-2 h-32 flex flex-col items-center justify-around">
            <div className="text-sm text-[#795e5e]">
              {isScanning ? (
                <span>
                  Analyzing the target and establishing its footprint. Stand by
                  for intel
                </span>
              ) : (
                <span>Target Analysis is done. The fingerprint table</span>
              )}
            </div>

            {isScanning ? (
              <div className="bg-[#6161611f] border border-[#353030] text-[#4b4b4b] py-1 px-6 rounded-lg text-sm">
                Scanning...
              </div>
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
