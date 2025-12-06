import { BookMarked, FolderUp } from "lucide-react";
import { useRef } from "react";
import { toast } from "../utils/toast";

interface RepositoryCardProps {
  selectedFile: File | null;
  formData: {
    applicationName: string;
    quickScan: boolean;
    demoMode: boolean;
    attackMode: boolean;
    targetIp: string;
    targetPort: string;
    autoExec: boolean;
  };
  isScanning: boolean;
  isUploading: boolean;
  onFileSelect: (file: File | null) => void;
  onInputChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
}

const RepositoryCard: React.FC<RepositoryCardProps> = ({
  selectedFile,
  formData,
  isScanning,
  isUploading,
  onFileSelect,
  onInputChange,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      // Validate file type
      if (!file.name.toLowerCase().endsWith(".zip")) {
        toast.error("Invalid file type", "Please select a ZIP file");
        onFileSelect(null);
        return;
      }

      // Validate file size (max 100MB)
      const maxSize = 100 * 1024 * 1024;
      if (file.size > maxSize) {
        toast.error("File too large", "Maximum file size is 100MB");
        onFileSelect(null);
        return;
      }

      onFileSelect(file);
      toast.success("File selected", file.name);
    }
  };

  const handleBrowseClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div>
      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".zip"
        onChange={handleFileChange}
        className="hidden"
      />

      {/*Heading*/}
      <div className="items-center flex gap-2">
        <div className="text-gray-400">
          <BookMarked className="w-5" />
        </div>
        <h2 className="text-blue-500 text-lg">Repository</h2>
      </div>

      <div className="">
        {/*Terminal Window*/}
        <div className="p-4 ml-10">
          <div className="items-center justify-between flex rounded-t-lg bg-[#2f2f2f] py-3 px-4">
            <span className="font-md text-gray-500">Project Path</span>

            <button
              onClick={handleBrowseClick}
              disabled={isScanning || isUploading}
              className="flex gap-1 rounded-md px-2 border border-transparent hover:border-white cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              <FolderUp className="w-4" />
              <span>Browse</span>
            </button>
          </div>

          <div className="border-[#2f2f2f] border items-center bg-[#0d0d0d] p-4 rounded-b-lg">
            <div className="border border-[#2f2f2f] rounded-lg p-4">
              <span className="text-sm text-blue-300">
                {selectedFile
                  ? `${selectedFile.name} (${(
                      selectedFile.size /
                      1024 /
                      1024
                    ).toFixed(2)} MB)`
                  : "Enter Source Code ZIP"}
              </span>
            </div>
          </div>
        </div>

        {/*Inputs And Options*/}
        <div className="flex items-center ml-24 gap-x-4">
          <span className="text-blue-300">Enter Application Name:</span>

          <input
            type="text"
            name="applicationName"
            value={formData.applicationName}
            onChange={onInputChange}
            disabled={isScanning || isUploading}
            className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm disabled:opacity-30 disabled:cursor-not-allowed"
            placeholder="My App"
          />
        </div>

        <div className="flex items-center ml-24 gap-x-4 mt-4">
          <div className="gap-x-4 flex items-center">
            <span className="text-blue-300">Quick Scan</span>

            <input
              type="checkbox"
              name="quickScan"
              checked={formData.quickScan}
              onChange={onInputChange}
              disabled={isScanning || isUploading}
              className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm disabled:opacity-30 disabled:cursor-not-allowed"
            />
          </div>

          <div className="gap-x-4 flex items-center">
            <span className="text-blue-300">Demo Mode</span>

            <input
              type="checkbox"
              name="demoMode"
              checked={formData.demoMode}
              onChange={onInputChange}
              disabled={isScanning || isUploading}
              className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm disabled:opacity-30 disabled:cursor-not-allowed"
            />
          </div>
        </div>

        <div className="flex items-center ml-24 gap-x-4 mt-4">
          <div className="gap-x-4 flex items-center">
            <span className="text-blue-300">Attack Mode (Stage 3)</span>

            <input
              type="checkbox"
              name="attackMode"
              checked={formData.attackMode}
              onChange={onInputChange}
              disabled={isScanning || isUploading}
              className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm disabled:opacity-30 disabled:cursor-not-allowed"
            />
          </div>

          <span>IP:</span>
          <input
            type="text"
            name="targetIp"
            value={formData.targetIp}
            onChange={onInputChange}
            placeholder="192.168.x.x"
            disabled={!formData.attackMode || isScanning || isUploading}
            className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm w-[15vw] disabled:opacity-30 disabled:cursor-not-allowed"
          />

          <span>Port:</span>
          <input
            type="text"
            name="targetPort"
            value={formData.targetPort}
            onChange={onInputChange}
            placeholder="80"
            disabled={!formData.attackMode || isScanning || isUploading}
            className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm w-[10vw] disabled:opacity-30 disabled:cursor-not-allowed"
          />

          <span>Auto Execute:</span>
          <input
            type="checkbox"
            name="autoExec"
            checked={formData.autoExec}
            onChange={onInputChange}
            disabled={!formData.attackMode || isScanning || isUploading}
            className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm disabled:opacity-30 disabled:cursor-not-allowed"
          />
        </div>
      </div>
    </div>
  );
};

export default RepositoryCard;
