import { ArrowRight, Crosshair } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select";

const ReconTargetCard = () => {
  return (
    <div>
      {/*Heading*/}
      <div className="items-center flex gap-2">
        <div className="text-gray-400">
          <Crosshair className="w-5" />
        </div>
        <h2 className="text-blue-500 text-lg">Recon Target</h2>
      </div>

      {/*Terminal Window */}
      <div className="p-4 ml-10">
        <div className="items-center justify-between flex rounded-t-lg bg-[#2f2f2f] py-3 px-4">
          <span className="font-md text-gray-500">Enter the Target's</span>
        </div>

        <div className="border-[#2f2f2f] border items-center bg-[#0d0d0d] p-4 rounded-b-lg">
          <div className="border border-[#2f2f2f] rounded-lg p-3">
            <div className="w-full focus:outline-none flex">
              <input
                type="text"
                name="targetInfo"
                value={""}
                onChange={() => {}}
                placeholder="IP / URL / DOMAIN"
                className="w-full bg-transparent text-md text-blue-300 placeholder-blue-300/50 active:outline-none"
              />
              <button className="rounded-md border border-[#4b4b4b] text-[#4b4b4b] px-1">
                <ArrowRight className="w-5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/*Inputs And Options*/}
      <div className="flex items-center ml-24 gap-x-4">
        <span className="text-blue-300">Enter Name:</span>

        <input
          type="text"
          name="applicationName"
          value={""}
          onChange={() => {}}
          disabled={false}
          className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm disabled:opacity-30 disabled:cursor-not-allowed"
          placeholder="My App"
        />
      </div>
    </div>
  );
};

export default ReconTargetCard;
