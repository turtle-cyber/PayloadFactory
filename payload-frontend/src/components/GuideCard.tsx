import { ArrowRight, Crosshair, Signpost } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select";

const GuideCard = () => {
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

        <div className="border-[#2f2f2f] border items-center bg-[#0d0d0d] p-4 rounded-b-lg h-[40vh] overflow-auto"></div>
      </div>
    </div>
  );
};

export default GuideCard;
