import ExploitGenerationCard from "@/components/ExploitGenerationCard";
import FingerprintTable from "@/components/FingerprintTable";
import GuideCard from "@/components/GuideCard";
import ReconTargetCard from "@/components/ReconTargetCard";

const ReconPage = () => {
  return (
    <div>
      <div className="overflow-auto text-white pb-6">
        <div className="max-w-6xl mx-auto px-6 space-y-6">
          <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
            <ReconTargetCard />
          </div>

          {/*Fingerprints Table */}
          <div>
            <FingerprintTable />
          </div>

          {/*Guide Card */}
          <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
            <GuideCard />
          </div>

          {/*Exploit Generation Window */}
          <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
            <ExploitGenerationCard />
            <button className="self-center p-2 bg-[#F37878] rounded-lg">
              Generate
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReconPage;
