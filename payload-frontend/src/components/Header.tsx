import { Link, useLocation } from "react-router-dom";
import { logo } from "../helpers/assetExport";
import {
  Bot,
  Compass,
  NotebookPen,
  SquareTerminal,
  Swords,
} from "lucide-react";

const Header: React.FC = () => {
  const location = useLocation();

  const isActive = (path: string): boolean => {
    return location.pathname === path;
  };

  return (
    <header className="fixed top-0 left-0 right-0 z-50 pt-2 backdrop-blur-md">
      <nav className="px-48 mx-auto">
        <div className="flex items-center justify-between border-[#C93D3D] border rounded-xl p-3">
          {/* Logo */}
          <Link to="/" className="text-2xl font-bold tracking-wider">
            <img src={logo} width={180} />
          </Link>

          {/* Navigation Menu */}
          <div className="flex items-center space-x-8">
            <Link
              to="/recon"
              className={`flex items-center space-x-2 transition-colors duration-200 ${
                isActive("/recon") || isActive("/recon/history")
                  ? "text-red-400"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <Compass className="w-5" />
              <span className="font-medium">Recon</span>
            </Link>

            <Link
              to="/scan"
              className={`flex items-center space-x-2 transition-colors duration-200 ${
                isActive("/scan")
                  ? "text-red-400"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <Swords />
              <span className="font-medium">Exploit Builder</span>
            </Link>

            <Link
              to="/agent"
              className={`flex items-center space-x-2 transition-colors duration-200 ${
                isActive("/agent")
                  ? "text-red-400"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <Bot className="w-5" />
              <span className="font-medium">Agent Logs</span>
            </Link>

            <Link
              to="/command-center"
              className={`flex items-center space-x-2 transition-colors duration-200 ${
                isActive("/command-center")
                  ? "text-red-400"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <SquareTerminal className="w-5" />
              <span className="font-medium">Command Center</span>
            </Link>

            <Link
              to="/results"
              className={`flex items-center space-x-2 transition-colors duration-200 ${
                isActive("/results")
                  ? "text-red-400"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <NotebookPen className="w-5" />
              <span className="font-medium">Results</span>
            </Link>
          </div>
        </div>

        {/* Red line separator */}
        {/* <div className="mt-4 h-px bg-gradient-to-r from-transparent via-red-500 to-transparent opacity-30" /> */}
      </nav>
    </header>
  );
};

export default Header;
