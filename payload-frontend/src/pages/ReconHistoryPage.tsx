import ReconHistoryTable from "@/components/ReconHistoryTable";
import { GET_RECON_HISTORY } from "@/endpoints/recon.endpoints";
import { http } from "@/utils/http";
import { ListFilter, ChevronDown } from "lucide-react";
import { useEffect, useRef, useState, useMemo } from "react";
import { toast } from "sonner";

interface ApiHistoryData {
  scan_id: string;
  scan_name: string;
  ip: string;
  status: string;
  exec_time: string;
  date: string;
}

type DateFilter = "all" | "1day" | "2days" | "7days";

const filterOptions: { value: DateFilter; label: string }[] = [
  { value: "all", label: "All Time" },
  { value: "1day", label: "Last 1 Day" },
  { value: "2days", label: "Last 2 Days" },
  { value: "7days", label: "Last 7 Days" },
];

function useGetReconHistory() {
  const [historyData, setHistoryData] = useState<ApiHistoryData[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const hasFetched = useRef(false);

  const fetchHistory = async () => {
    setHistoryLoading(true);
    try {
      const response = await http.get(GET_RECON_HISTORY);

      // Handle API response structure
      const data = response?.data?.recons || [];
      const reconsArray = Array.isArray(data) ? data : [];

      setHistoryData(reconsArray);

      if (reconsArray.length > 0) {
        toast.success(
          "Scans loaded successfully - " +
            `Found ${reconsArray.length} entrie(s)`
        );
      }
    } catch (error) {
      toast.error("Error fetching scans");
      console.error("Error fetching scans:", error);
      setHistoryData([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    if (!hasFetched.current) {
      hasFetched.current = true;
      fetchHistory();
    }
  }, []);

  return { historyData, historyLoading, fetchHistory };
}

function filterByDate(
  data: ApiHistoryData[],
  filter: DateFilter
): ApiHistoryData[] {
  if (filter === "all") return data;

  const now = new Date();
  const daysMap: Record<DateFilter, number> = {
    all: 0,
    "1day": 1,
    "2days": 2,
    "7days": 7,
  };

  const days = daysMap[filter];
  const cutoffDate = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);

  return data.filter((item) => {
    const itemDate = new Date(item.date);
    return itemDate >= cutoffDate;
  });
}

const ReconHistoryPage = () => {
  const { historyData, historyLoading } = useGetReconHistory();
  const [dateFilter, setDateFilter] = useState<DateFilter>("all");
  const [isFilterOpen, setIsFilterOpen] = useState(false);

  const filteredData = useMemo(
    () => filterByDate(historyData, dateFilter),
    [historyData, dateFilter]
  );

  const currentFilterLabel =
    filterOptions.find((opt) => opt.value === dateFilter)?.label || "All Time";

  return (
    <div className="overflow-auto text-white">
      <div className="px-48 mx-auto space-y-6">
        <div className="flex justify-end">
          <div className="relative">
            <div
              className="p-2 flex items-center justify-center gap-2 rounded-lg text-gray-300 hover:text-gray-100 bg-[#f378781f] border border-[#462222] cursor-pointer hover:bg-[#f3787833] transition-all"
              onClick={() => setIsFilterOpen(!isFilterOpen)}
            >
              <ListFilter className="w-4 h-4" />
              <span>{currentFilterLabel}</span>
              <ChevronDown
                className={`w-4 h-4 transition-transform ${
                  isFilterOpen ? "rotate-180" : ""
                }`}
              />
            </div>

            {isFilterOpen && (
              <div className="absolute right-0 mt-2 w-40 bg-[#1a1714] border border-[#462222] rounded-lg shadow-lg z-10 overflow-hidden">
                {filterOptions.map((option) => (
                  <div
                    key={option.value}
                    className={`px-4 py-2 cursor-pointer transition-all ${
                      dateFilter === option.value
                        ? "bg-[#f3787833] text-red-400"
                        : "text-gray-300 hover:bg-[#f378781f] hover:text-gray-100"
                    }`}
                    onClick={() => {
                      setDateFilter(option.value);
                      setIsFilterOpen(false);
                    }}
                  >
                    {option.label}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div>
          <ReconHistoryTable data={filteredData} loading={historyLoading} />
        </div>
      </div>
    </div>
  );
};

export default ReconHistoryPage;
