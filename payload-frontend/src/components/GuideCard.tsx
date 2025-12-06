import { ArrowRight, Crosshair, Signpost } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select";

interface GuideCardProps {
  analysis: string;
}

const GuideCard: React.FC<GuideCardProps> = ({ analysis }) => {
  return (
    <div>
      {/*Heading*/}
      <div className="items-center flex gap-2">
        <div className="text-gray-400">
          <Signpost className="w-5" />
        </div>
        <h2 className="text-blue-500 text-lg">Guide</h2>
      </div>

      {/*Terminal Window */}
      <div className="p-4">
        <div className="items-center justify-between flex rounded-t-lg bg-[#2f2f2f] py-2 px-4">
          <span className="font-md text-gray-500">
            Exploitation Steps and Source Links
          </span>
        </div>

        <div className="border-[#2f2f2f] border bg-[#0d0d0d] p-4 rounded-b-lg h-[40vh] overflow-auto">
          {analysis ? (
            <pre className="text-gray-300 text-sm font-mono whitespace-pre-wrap">
              {analysis}
            </pre>
          ) : (
            <div className="flex items-center justify-center h-full">
              <p className="text-gray-500 text-sm">
                No analysis available. Run a scan to generate exploitation
                guidance.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default GuideCard;
