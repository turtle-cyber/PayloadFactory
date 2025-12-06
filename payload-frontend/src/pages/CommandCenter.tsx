import { useEffect, useRef, useState } from "react";
import { http } from "../utils/http";
import { toast } from "sonner";
import {
  GET_PLATFORM_METRICS,
  GET_RECON_ANALYTICS,
} from "../endpoints/commandcenter.endpoints";
import EChart from "../components/EChart";

interface PlatformMetrics {
  totalRepos: number;
  totalExploits: number;
  activeScans: number;
  pendingVulnerabilities: number;
}

interface ReconAnalytics {
  reposBySeverity: {
    high: number;
    medium: number;
    low: number;
  };
  severityHeatmap: Array<{
    dayOfWeek: number;
    week: number;
    intensity: number;
    scanCount: number;
    exploitCount: number;
    date: string;
    scans: Array<{
      name: string;
      exploits: number;
    }>;
  }>;
  exploitsByType: Array<{
    cwe: string;
    count: number;
  }>;
  exploitsByOwasp: Record<string, number>;
}

function useGetPlatformMetrics() {
  const [platformMetricsData, setPlatformMetricsData] =
    useState<PlatformMetrics | null>(null);
  const [platformMetricsLoading, setPlatformMetricsLoading] =
    useState<boolean>(false);
  const hasFetched = useRef(false);

  const fetchPlatformMetrics = async () => {
    setPlatformMetricsLoading(true);
    try {
      const response = await http.get(GET_PLATFORM_METRICS);

      // Handle API response data structure
      const data = response?.data?.data || {};

      if (response.status === 200) {
        toast.success("Metrics loaded successfully");
        setPlatformMetricsData(data);
      }
    } catch (error) {
      toast.error("Error fetching metrics");
      console.error("Error fetching metrics:", error);
      setPlatformMetricsData(null);
    } finally {
      setPlatformMetricsLoading(false);
    }
  };

  useEffect(() => {
    if (!hasFetched.current) {
      hasFetched.current = true;
      fetchPlatformMetrics();
    }
  }, []);

  return { platformMetricsData, platformMetricsLoading, fetchPlatformMetrics };
}

function useGetReconAnalytics() {
  const [reconAnalyticsData, setReconAnalyticsData] =
    useState<ReconAnalytics | null>(null);
  const [reconAnalyticsLoading, setReconAnalyticsLoading] =
    useState<boolean>(false);
  const hasFetched = useRef(false);

  const fetchReconAnalytics = async () => {
    setReconAnalyticsLoading(true);
    try {
      const response = await http.get(GET_RECON_ANALYTICS);
      console.log(response);
      // Handle API response data structure
      const data = response?.data?.data || {};

      if (response.status === 200) {
        toast.success("Recon Analytics Data loaded successfully");
        setReconAnalyticsData(data);
      }
    } catch (error) {
      toast.error("Error fetching metrics");
      console.error("Error fetching metrics:", error);
      setReconAnalyticsData(null);
    } finally {
      setReconAnalyticsLoading(false);
    }
  };

  useEffect(() => {
    if (!hasFetched.current) {
      hasFetched.current = true;
      fetchReconAnalytics();
    }
  }, []);

  return { reconAnalyticsData, reconAnalyticsLoading, fetchReconAnalytics };
}

const CommandCenter: React.FC = () => {
  const { platformMetricsData, platformMetricsLoading } =
    useGetPlatformMetrics();
  const { reconAnalyticsData, reconAnalyticsLoading } = useGetReconAnalytics();

  // Map API data to metrics array
  const metrics = [
    {
      label: "Total Repos Uploaded",
      value: platformMetricsData?.totalRepos?.toString() || "0",
    },
    {
      label: "Total Exploits Generated",
      value: platformMetricsData?.totalExploits?.toString() || "0",
    },
    {
      label: "Active Scans",
      value: platformMetricsData?.activeScans?.toString() || "0",
    },
    {
      label: "Pending Vulnerabilities",
      value: platformMetricsData?.pendingVulnerabilities?.toString() || "0",
    },
  ];

  // Transform API data for charts
  const severityChartData =
    reconAnalyticsData?.reposBySeverity &&
    (reconAnalyticsData.reposBySeverity.high > 0 ||
      reconAnalyticsData.reposBySeverity.medium > 0 ||
      reconAnalyticsData.reposBySeverity.low > 0)
      ? [
          { name: "HIGH", value: reconAnalyticsData.reposBySeverity.high },
          { name: "MEDIUM", value: reconAnalyticsData.reposBySeverity.medium },
          { name: "LOW", value: reconAnalyticsData.reposBySeverity.low },
        ]
      : null;

  const exploitTypesData =
    reconAnalyticsData?.exploitsByType &&
    reconAnalyticsData.exploitsByType.length > 0
      ? reconAnalyticsData.exploitsByType.map(
          (item: { cwe: string; count: number }) => ({
            name: item.cwe,
            value: item.count,
          })
        )
      : null;

  // Generate colors for exploit types based on count
  const exploitTypesColors =
    exploitTypesData && exploitTypesData.length > 0
      ? exploitTypesData.map((_, index) => {
          const colors = [
            "#ef4444",
            "#f97316",
            "#eab308",
            "#84cc16",
            "#06b6d4",
            "#3b82f6",
            "#8b5cf6",
            "#ec4899",
            "#f43f5e",
            "#14b8a6",
          ];
          return colors[index % colors.length];
        })
      : [];

  // Transform heatmap data
  const heatmapChartData = (() => {
    const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const weeks = ["Week 1", "Week 2", "Week 3", "Week 4"];

    // Create a map to store existing data by "dayIndex,weekIndex" key
    const existingDataMap = new Map<
      string,
      {
        value: [number, number, number];
        scanCount: number;
        scans: Array<{ name: string; exploits: number }>;
        date: string;
      }
    >();

    // Populate map with actual data from API
    if (reconAnalyticsData?.severityHeatmap) {
      reconAnalyticsData.severityHeatmap.forEach(
        (item: {
          dayOfWeek: number;
          week: number;
          intensity: number;
          scanCount: number;
          exploitCount: number;
          date: string;
          scans: Array<{ name: string; exploits: number }>;
        }) => {
          // dayOfWeek: 1=Sunday, 2=Monday, etc. Convert to 0=Monday
          const dayIndex = item.dayOfWeek === 1 ? 6 : item.dayOfWeek - 2;
          const weekIndex = Math.min(item.week % 4, 3);
          const key = `${dayIndex},${weekIndex}`;
          existingDataMap.set(key, {
            value: [dayIndex, weekIndex, Math.round(item.intensity * 10)],
            scanCount: item.scanCount,
            scans: item.scans,
            date: item.date,
          });
        }
      );
    }

    // Generate complete grid - fill missing cells with empty data
    const data: Array<{
      value: [number, number, number];
      scanCount: number;
      scans: Array<{ name: string; exploits: number }>;
      date: string;
    }> = [];

    for (let weekIndex = 0; weekIndex < weeks.length; weekIndex++) {
      for (let dayIndex = 0; dayIndex < days.length; dayIndex++) {
        const key = `${dayIndex},${weekIndex}`;
        if (existingDataMap.has(key)) {
          data.push(existingDataMap.get(key)!);
        } else {
          // Empty cell with value 0 - use same format as filled cells
          data.push({
            value: [dayIndex, weekIndex, 0],
            scanCount: 0,
            scans: [],
            date: "",
          });
        }
      }
    }

    return { xAxisData: days, yAxisData: weeks, data };
  })();

  // Transform OWASP radar data - always show 6 vertices
  const owaspRadarData = (() => {
    if (
      !reconAnalyticsData?.exploitsByOwasp ||
      Object.keys(reconAnalyticsData.exploitsByOwasp).length === 0
    ) {
      return null;
    }

    const owaspData = reconAnalyticsData.exploitsByOwasp;
    const categories: string[] = [];
    const values: number[] = [];

    // Add actual categories from API
    Object.entries(owaspData).forEach(([category, count]) => {
      categories.push(category.replace("A0", "A").substring(0, 30));
      values.push(count as number);
    });

    // Fill remaining slots up to 6 with N/A
    const remainingSlots = 6 - categories.length;
    for (let i = 0; i < remainingSlots; i++) {
      categories.push("N/A");
      values.push(0);
    }

    const maxValue = Math.max(...values.filter((v) => v > 0), 10);

    return {
      indicator: categories.map((cat) => ({
        name: cat,
        max: maxValue,
      })),
      data: [
        {
          value: values,
          name: "Exploits",
        },
      ],
    };
  })();

  return (
    <div className="min-h-screen text-white px-8 py-8">
      <div className="max-w-6xl mx-auto">
        {/* Platform Metrics */}
        <div className="mb-8">
          <h2 className="text-xl font-semibold mb-4">Platform Metrics</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {platformMetricsLoading ? (
              // Skeleton Loader
              <>
                {[...Array(4)].map((_, index) => (
                  <div
                    key={index}
                    className="glassmorphism-card rounded-lg p-6 border border-red-500/20 animate-pulse"
                  >
                    <div className="h-4 bg-gray-700 rounded w-3/4 mb-2"></div>
                    <div className="h-10 bg-gray-700 rounded w-1/2"></div>
                  </div>
                ))}
              </>
            ) : (
              // Actual Metrics Cards
              metrics.map((metric, index) => (
                <div
                  key={index}
                  className="glassmorphism-card rounded-lg p-6 border border-red-500/20"
                >
                  <p className="text-sm text-gray-400 mb-2">{metric.label}</p>
                  <p className="text-4xl font-bold">{metric.value}</p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Recon Analytics */}
        <div>
          <h2 className="text-xl font-semibold mb-4">Recon Analytics</h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Top Repos By Severity - Donut Chart */}
            <div className="glassmorphism-card rounded-lg p-6 border border-red-500/20">
              <h3 className="text-lg font-semibold mb-6">
                Top Repos By Severity
              </h3>
              {reconAnalyticsLoading ? (
                <div className="flex items-center justify-center h-[350px]">
                  <div className="animate-pulse text-gray-400">
                    Loading chart...
                  </div>
                </div>
              ) : severityChartData ? (
                <EChart
                  type="pie"
                  data={severityChartData}
                  height="350px"
                  loading={false}
                  radius={["40%", "60%"]}
                  colors={["#ef4444", "#eab308", "#06b6d4"]}
                />
              ) : (
                <div className="flex items-center justify-center h-[350px] text-gray-500">
                  No data available
                </div>
              )}
            </div>

            {/* Severity Heatmap */}
            <div className="glassmorphism-card rounded-lg p-6 border border-red-500/20">
              <h3 className="text-lg font-semibold mb-6">Severity Heatmap</h3>
              {reconAnalyticsLoading ? (
                <div className="flex items-center justify-center h-[350px]">
                  <div className="animate-pulse text-gray-400">
                    Loading chart...
                  </div>
                </div>
              ) : heatmapChartData ? (
                <EChart
                  type="heatmap"
                  data={heatmapChartData}
                  height="350px"
                  loading={false}
                />
              ) : (
                <div className="flex items-center justify-center h-[350px] text-gray-500">
                  No data available
                </div>
              )}
            </div>

            {/* Exploit By Type - Bar Chart */}
            <div className="glassmorphism-card rounded-lg p-6 border border-red-500/20">
              <h3 className="text-lg font-semibold mb-6">Exploit By Type</h3>
              {reconAnalyticsLoading ? (
                <div className="flex items-center justify-center h-[350px]">
                  <div className="animate-pulse text-gray-400">
                    Loading chart...
                  </div>
                </div>
              ) : exploitTypesData ? (
                <EChart
                  type="bar"
                  data={exploitTypesData}
                  height="350px"
                  loading={false}
                  horizontal={false}
                  colors={exploitTypesColors}
                />
              ) : (
                <div className="flex items-center justify-center h-[350px] text-gray-500">
                  No data available
                </div>
              )}
            </div>

            {/* Exploit By OWASP - Radar Chart */}
            <div className="glassmorphism-card rounded-lg p-6 border border-red-500/20">
              <h3 className="text-lg font-semibold mb-6">Exploit By OWASP</h3>
              {reconAnalyticsLoading ? (
                <div className="flex items-center justify-center h-[350px]">
                  <div className="animate-pulse text-gray-400">
                    Loading chart...
                  </div>
                </div>
              ) : owaspRadarData ? (
                <EChart
                  type="radar"
                  data={owaspRadarData}
                  height="350px"
                  loading={false}
                  colors={["#ef4444"]}
                />
              ) : (
                <div className="flex items-center justify-center h-[350px] text-gray-500">
                  No data available
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CommandCenter;
