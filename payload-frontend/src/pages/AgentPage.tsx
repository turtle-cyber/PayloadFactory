import React from "react";

const AgentPage = () => {
  return (
    <div className="overflow-auto text-white">
      <div className="max-w-6xl mx-auto px-6 space-y-6">
        <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
          <h2 className="text-xl font-semibold text-white">
            Run the following command on your linux based target machine
          </h2>
        </div>
        <div className="glassmorphism-card p-8 rounded-lg border border-red-500/20">
          {/*Logs*/}
        </div>
      </div>
    </div>
  );
};

export default AgentPage;
