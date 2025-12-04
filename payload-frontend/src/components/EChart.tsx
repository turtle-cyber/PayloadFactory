import { useEffect, useRef } from "react";
import * as echarts from "echarts";

export type ChartType = "pie" | "bar" | "heatmap" | "radar" | "line";

interface BaseChartProps {
  type: ChartType;
  height?: string;
  className?: string;
  loading?: boolean;
}

// Pie Chart Props
export interface PieChartData {
  name: string;
  value: number;
}

interface PieChartProps extends BaseChartProps {
  type: "pie";
  data: PieChartData[];
  title?: string;
  radius?: [string, string]; // Inner and outer radius for donut chart
  colors?: string[];
}

// Bar Chart Props
export interface BarChartData {
  name: string;
  value: number;
}

interface BarChartProps extends BaseChartProps {
  type: "bar";
  data: BarChartData[];
  title?: string;
  horizontal?: boolean;
  colors?: string[];
}

// Heatmap Chart Props
export interface HeatmapChartData {
  xAxisData: string[];
  yAxisData: string[];
  data: [number, number, number][]; // [x, y, value]
}

interface HeatmapChartProps extends BaseChartProps {
  type: "heatmap";
  data: HeatmapChartData;
  title?: string;
  colors?: string[];
}

// Radar Chart Props
export interface RadarChartData {
  indicator: { name: string; max: number }[];
  data: {
    value: number[];
    name?: string;
  }[];
}

interface RadarChartProps extends BaseChartProps {
  type: "radar";
  data: RadarChartData;
  title?: string;
  colors?: string[];
}

// Line Chart Props
export interface LineChartData {
  xAxisData: string[];
  series: {
    name: string;
    data: number[];
  }[];
}

interface LineChartProps extends BaseChartProps {
  type: "line";
  data: LineChartData;
  title?: string;
  colors?: string[];
}

export type EChartProps =
  | PieChartProps
  | BarChartProps
  | HeatmapChartProps
  | RadarChartProps
  | LineChartProps;

const EChart: React.FC<EChartProps> = (props) => {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstanceRef = useRef<echarts.ECharts | null>(null);

  const { type, height = "400px", className = "", loading = false } = props;

  useEffect(() => {
    if (!chartRef.current) return;

    // Initialize chart
    if (!chartInstanceRef.current) {
      chartInstanceRef.current = echarts.init(chartRef.current, "dark");
    }

    const chart = chartInstanceRef.current;

    // Show loading if needed
    if (loading) {
      chart.showLoading({
        text: "Loading...",
        color: "#ef4444",
        textColor: "#ffffff",
        maskColor: "rgba(0, 0, 0, 0.8)",
      });
      return;
    } else {
      chart.hideLoading();
    }

    // Generate options based on chart type
    let option: echarts.EChartsOption = {};

    switch (type) {
      case "pie": {
        const pieProps = props as PieChartProps;
        option = {
          title: pieProps.title
            ? {
                text: pieProps.title,
                left: "center",
                textStyle: { color: "#ffffff" },
              }
            : undefined,
          tooltip: {
            trigger: "item",
            backgroundColor: "rgba(0, 0, 0, 0.8)",
            borderColor: "#ef4444",
            textStyle: { color: "#ffffff" },
          },
          legend: {
            orient: window.innerWidth < 768 ? "horizontal" : "vertical",
            right: window.innerWidth < 768 ? "center" : "10%",
            bottom: window.innerWidth < 768 ? "0%" : undefined,
            top: window.innerWidth < 768 ? undefined : "center",
            textStyle: { color: "#9ca3af" },
          },
          color: pieProps.colors || [
            "#ef4444",
            "#eab308",
            "#06b6d4",
            "#8b5cf6",
            "#10b981",
          ],
          series: [
            {
              type: "pie",
              radius: pieProps.radius || ["40%", "70%"],
              avoidLabelOverlap: false,
              itemStyle: {
                borderRadius: 10,
                borderColor: "#1a1a1a",
                borderWidth: 2,
              },
              label: {
                show: false,
              },
              emphasis: {
                label: {
                  show: true,
                  fontSize: 16,
                  fontWeight: "bold",
                  color: "#ffffff",
                },
              },
              labelLine: {
                show: false,
              },
              data: pieProps.data,
            },
          ],
        };
        break;
      }

      case "bar": {
        const barProps = props as BarChartProps;
        const isHorizontal = barProps.horizontal ?? false;

        option = {
          title: barProps.title
            ? {
                text: barProps.title,
                left: "center",
                textStyle: { color: "#ffffff" },
              }
            : undefined,
          tooltip: {
            trigger: "axis",
            axisPointer: { type: "shadow" },
            backgroundColor: "rgba(0, 0, 0, 0.8)",
            borderColor: "#ef4444",
            textStyle: { color: "#ffffff" },
          },
          grid: {
            left: isHorizontal ? "15%" : "3%",
            right: "4%",
            bottom: "3%",
            containLabel: true,
          },
          xAxis: isHorizontal
            ? {
                type: "value",
                axisLine: { lineStyle: { color: "#4b5563" } },
                axisLabel: { color: "#9ca3af" },
                splitLine: { lineStyle: { color: "#374151" } },
              }
            : {
                type: "category",
                data: barProps.data.map((item) => item.name),
                axisLine: { lineStyle: { color: "#4b5563" } },
                axisLabel: { color: "#9ca3af" },
              },
          yAxis: isHorizontal
            ? {
                type: "category",
                data: barProps.data.map((item) => item.name),
                axisLine: { lineStyle: { color: "#4b5563" } },
                axisLabel: { color: "#9ca3af" },
              }
            : {
                type: "value",
                axisLine: { lineStyle: { color: "#4b5563" } },
                axisLabel: { color: "#9ca3af" },
                splitLine: { lineStyle: { color: "#374151" } },
              },
          color: barProps.colors || ["#ef4444"],
          series: [
            {
              type: "bar",
              data: barProps.data.map((item, index) => ({
                value: item.value,
                itemStyle: {
                  color:
                    barProps.colors && barProps.colors[index]
                      ? barProps.colors[index]
                      : barProps.colors?.[0] || "#ef4444",
                  borderRadius: isHorizontal ? [0, 4, 4, 0] : [4, 4, 0, 0],
                },
              })),
              emphasis: {
                itemStyle: {
                  shadowBlur: 10,
                  shadowColor: "rgba(0, 0, 0, 0.5)",
                },
              },
            },
          ],
        };
        break;
      }

      case "heatmap": {
        const heatmapProps = props as HeatmapChartProps;

        option = {
          title: heatmapProps.title
            ? {
                text: heatmapProps.title,
                left: "center",
                textStyle: { color: "#ffffff" },
              }
            : undefined,
          tooltip: {
            position: "top",
            backgroundColor: "rgba(0, 0, 0, 0.8)",
            borderColor: "#ef4444",
            textStyle: { color: "#ffffff" },
          },
          grid: {
            left: "10%",
            right: "10%",
            top: "10%",
            bottom: "25%",
          },
          xAxis: {
            type: "category",
            data: heatmapProps.data.xAxisData,
            splitArea: { show: true },
            axisLine: { lineStyle: { color: "#4b5563" } },
            axisLabel: { color: "#9ca3af" },
          },
          yAxis: {
            type: "category",
            data: heatmapProps.data.yAxisData,
            splitArea: { show: true },
            axisLine: { lineStyle: { color: "#4b5563" } },
            axisLabel: { color: "#9ca3af" },
          },
          visualMap: {
            type: "piecewise",
            orient: "horizontal",
            left: "center",
            bottom: "2%",
            itemWidth: 12,
            itemHeight: 12,
            itemGap: 4,
            pieces: [
              { min: 0, max: 0, color: "#1a1a1a", label: "Less" },
              { min: 1, max: 2, color: "#7f1d1d" },
              { min: 3, max: 5, color: "#991b1b" },
              { min: 6, max: 8, color: "#dc2626" },
              { min: 9, max: 10, color: "#ef4444", label: "More" },
            ],
            textStyle: { color: "#9ca3af", fontSize: 10 },
            showLabel: true,
          },
          series: [
            {
              type: "heatmap",
              data: heatmapProps.data.data,
              label: {
                show: false,
              },
              emphasis: {
                itemStyle: {
                  shadowBlur: 10,
                  shadowColor: "rgba(239, 68, 68, 0.5)",
                },
              },
            },
          ],
        };
        break;
      }

      case "radar": {
        const radarProps = props as RadarChartProps;

        option = {
          title: radarProps.title
            ? {
                text: radarProps.title,
                left: "center",
                textStyle: { color: "#ffffff" },
              }
            : undefined,
          tooltip: {
            backgroundColor: "rgba(0, 0, 0, 0.8)",
            borderColor: "#ef4444",
            textStyle: { color: "#ffffff" },
            formatter: (params: any) => {
              const data = params.value;
              let result = `<strong>${params.name}</strong><br/>`;
              radarProps.data.indicator.forEach((item, index) => {
                const value = data[index];
                result += `${item.name}: ${value === 0 ? "N/A" : value}<br/>`;
              });
              return result;
            },
          },
          legend: {
            bottom: 0,
            textStyle: { color: "#9ca3af" },
          },
          color: radarProps.colors || ["#ef4444", "#eab308", "#06b6d4"],
          radar: {
            indicator: radarProps.data.indicator,
            splitArea: {
              areaStyle: {
                color: ["rgba(239, 68, 68, 0.05)", "rgba(239, 68, 68, 0.1)"],
              },
            },
            axisLine: {
              lineStyle: { color: "#4b5563" },
            },
            splitLine: {
              lineStyle: { color: "#374151" },
            },
            axisName: {
              color: "#9ca3af",
              fontSize: 11,
            },
          },
          series: [
            {
              type: "radar",
              data: radarProps.data.data,
              areaStyle: {
                opacity: 0.3,
              },
              emphasis: {
                lineStyle: {
                  width: 4,
                },
              },
            },
          ],
        };
        break;
      }

      case "line": {
        const lineProps = props as LineChartProps;

        option = {
          title: lineProps.title
            ? {
                text: lineProps.title,
                left: "center",
                textStyle: { color: "#ffffff" },
              }
            : undefined,
          tooltip: {
            trigger: "axis",
            backgroundColor: "rgba(0, 0, 0, 0.8)",
            borderColor: "#ef4444",
            textStyle: { color: "#ffffff" },
          },
          legend: {
            bottom: 0,
            textStyle: { color: "#9ca3af" },
          },
          grid: {
            left: "3%",
            right: "4%",
            bottom: "10%",
            containLabel: true,
          },
          xAxis: {
            type: "category",
            boundaryGap: false,
            data: lineProps.data.xAxisData,
            axisLine: { lineStyle: { color: "#4b5563" } },
            axisLabel: { color: "#9ca3af" },
          },
          yAxis: {
            type: "value",
            axisLine: { lineStyle: { color: "#4b5563" } },
            axisLabel: { color: "#9ca3af" },
            splitLine: { lineStyle: { color: "#374151" } },
          },
          color: lineProps.colors || ["#ef4444", "#eab308", "#06b6d4"],
          series: lineProps.data.series.map((s) => ({
            name: s.name,
            type: "line",
            data: s.data,
            smooth: true,
            emphasis: {
              focus: "series",
            },
          })),
        };
        break;
      }
    }

    chart.setOption(option, true);

    // Handle resize
    const handleResize = () => {
      chart.resize();
    };
    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
    };
  }, [props, loading]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (chartInstanceRef.current) {
        chartInstanceRef.current.dispose();
        chartInstanceRef.current = null;
      }
    };
  }, []);

  return <div ref={chartRef} style={{ height }} className={className} />;
};

export default EChart;
