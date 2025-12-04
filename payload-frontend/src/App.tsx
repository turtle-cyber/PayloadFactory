import React from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  useLocation,
} from "react-router-dom";
import { Toaster } from "sonner";
import Header from "./components/Header";
import LandingPage from "./pages/LandingPage";
import ScanPage from "./pages/ScanPage";
import CommandCenter from "./pages/CommandCenter";
import ResultsPage from "./pages/ResultsPage";
import { homeBg, dashboardBg } from "./helpers/assetExport";
import "./index.css";
import FindingPage from "./pages/FindingPage";

const AppContent: React.FC = () => {
  const location = useLocation();
  const isLandingPage = location.pathname === "/";
  const backgroundImage = isLandingPage ? homeBg : dashboardBg;

  return (
    <div className="relative min-h-screen bg-black text-white overflow-x-hidden">
      {/* Fixed Background - stays on all pages */}
      <div className="fixed inset-0 z-0">
        {/* Base background */}
        <div className="absolute inset-0 bg-black" />

        {/* Background code image with fade effect */}
        <div
          className="absolute inset-0 opacity-80"
          style={{
            backgroundImage: `url(${backgroundImage})`,
            backgroundSize: "cover",
            backgroundPosition: "center",
            backgroundRepeat: "no-repeat",
          }}
        />

        {/* Gradient overlays for fade effect */}
        <div className="absolute inset-0 bg-gradient-to-b from-black via-transparent to-black opacity-40" />
        <div className="absolute inset-0 bg-gradient-to-r from-black via-transparent to-black opacity-20" />

        {/* Subtle grid pattern */}
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: `
              linear-gradient(rgba(255, 0, 0, 0.1) 1px, transparent 1px),
              linear-gradient(90deg, rgba(255, 0, 0, 0.1) 1px, transparent 1px)
            `,
            backgroundSize: "50px 50px",
          }}
        />

        {/* Vignette effect */}
        <div
          className="absolute inset-0 bg-radial-gradient opacity-50"
          style={{
            background:
              "radial-gradient(circle at center, transparent 0%, rgba(0,0,0,0.8) 100%)",
          }}
        />
      </div>

      {/* Fixed Header */}
      <Header />

      {/* Main Content Area - with padding to account for fixed header */}
      <main className="relative z-10 pt-20">
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/scan" element={<ScanPage />} />
          <Route path="/command-center" element={<CommandCenter />} />
          <Route path="/results" element={<ResultsPage />} />
          <Route path="/results/:scan_id" element={<FindingPage />} />
        </Routes>
      </main>

      {/* Ambient red glow effects */}
      <div className="fixed top-0 left-1/4 w-96 h-96 bg-red-600/10 rounded-full blur-[150px] pointer-events-none z-0" />
      <div className="fixed bottom-0 right-1/4 w-96 h-96 bg-red-600/10 rounded-full blur-[150px] pointer-events-none z-0" />
    </div>
  );
};

const App: React.FC = () => {
  return (
    <Router>
      <Toaster
        position="top-right"
        expand={false}
        richColors
        closeButton
        theme="dark"
        toastOptions={{
          style: {
            background: "rgba(17, 17, 17, 0.95)",
            border: "1px solid rgba(255, 255, 255, 0.1)",
            backdropFilter: "blur(10px)",
          },
        }}
      />
      <AppContent />
    </Router>
  );
};

export default App;
