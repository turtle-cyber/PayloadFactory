import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { FolderSymlink, FolderUp } from "lucide-react";

interface ExportSettingsCardProps {
  exportProjectPath: string;
  exportFormat: string;
  onInputChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onFormatChange: (value: string) => void;
  onBrowse?: () => void;
}

const ExportSettingsCard: React.FC<ExportSettingsCardProps> = ({
  exportProjectPath,
  exportFormat,
  onInputChange,
  onFormatChange,
  onBrowse,
}) => {
  return (
    <div>
      {/*Heading*/}
      <div className="items-center flex gap-2">
        <div className="text-gray-400">
          <FolderSymlink className="w-5" />
        </div>
        <h2 className="text-blue-500 text-lg">Export Settings</h2>
      </div>

      {/*Terminal Window */}
      <div className="p-4 ml-10">
        <div className="items-center justify-between flex rounded-t-lg bg-[#2f2f2f] py-3 px-4">
          <span className="font-md text-gray-500">Project Path</span>

          <button
            onClick={onBrowse}
            className="flex gap-1 rounded-md px-2 border border-transparent hover:border-white cursor-pointer transition-all"
          >
            <FolderUp className="w-4" />
            <span>Browse</span>
          </button>
        </div>

        <div className="border-[#2f2f2f] border items-center bg-[#0d0d0d] p-4 rounded-b-lg">
          <div className="border border-[#2f2f2f] rounded-lg p-4">
            <input
              type="text"
              name="exportProjectPath"
              value={exportProjectPath}
              onChange={onInputChange}
              placeholder="Enter Output File Path"
              className="w-full bg-transparent text-sm text-blue-300 placeholder-blue-300/50 focus:outline-none"
            />
          </div>
        </div>
      </div>

      {/*Inputs And Options*/}
      <div className="flex items-center ml-24 gap-x-4">
        <span className="text-blue-300">Export Format:</span>

        <Select value={exportFormat} onValueChange={onFormatChange}>
          <SelectTrigger className="w-full max-w-sm bg-black/50 border border-gray-700/50 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-red-500/50 transition-colors">
            <SelectValue placeholder="Select export format" />
          </SelectTrigger>
          <SelectContent className="bg-gray-900 border border-gray-700/50">
            <SelectItem
              value="Excel.xlsx"
              className="text-white hover:bg-gray-800 focus:bg-gray-800 cursor-pointer"
            >
              Excel.xlsx
            </SelectItem>
            <SelectItem
              value="CSV.csv"
              className="text-white hover:bg-gray-800 focus:bg-gray-800 cursor-pointer"
            >
              CSV.csv
            </SelectItem>
            <SelectItem
              value="JSON.json"
              className="text-white hover:bg-gray-800 focus:bg-gray-800 cursor-pointer"
            >
              JSON.json
            </SelectItem>
            <SelectItem
              value="PDF.pdf"
              className="text-white hover:bg-gray-800 focus:bg-gray-800 cursor-pointer"
            >
              PDF.pdf
            </SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>
  );
};

export default ExportSettingsCard;
