import { Signpost } from "lucide-react";

interface GuideCardProps {
  analysis: string;
  acknowledgmentChecked: boolean;
  onAcknowledgmentChange: (checked: boolean) => void;
}

const GuideCard: React.FC<GuideCardProps> = ({
  analysis,
  acknowledgmentChecked,
  onAcknowledgmentChange
}) => {
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

      {/* Acknowledgment Checkbox */}
      <div className="mt-4 flex items-center gap-3 p-4 bg-[#1a1714] rounded-lg border border-[#2f2f2f]">
        <input
          type="checkbox"
          id="guide-acknowledgment"
          checked={acknowledgmentChecked}
          onChange={(e) => onAcknowledgmentChange(e.target.checked)}
          disabled={!analysis}
          className="w-5 h-5 cursor-pointer accent-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
        />
        <label
          htmlFor="guide-acknowledgment"
          className={`text-sm cursor-pointer select-none ${
            analysis ? 'text-gray-300' : 'text-gray-500'
          }`}
        >
          To proceed, acknowledge that you've read the guide.
        </label>
      </div>
    </div>
  );
};

export default GuideCard;
