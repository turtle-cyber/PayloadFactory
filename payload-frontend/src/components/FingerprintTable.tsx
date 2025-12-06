const FingerprintTable = () => {
  return (
    <>
      <div className="py-2 px-4 rounded-lg bg-[#2f2f2f]">
        <span>Fingerprints</span>
      </div>

      <div className="bg-[#1a1714] p-4 mt-2 h-[30vh] overflow-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left p-4 text-sm font-semibold text-gray-400">
                PORT
              </th>
              <th className="text-left p-4 text-sm font-semibold text-gray-400">
                STATE
              </th>
              <th className="text-left p-4 text-sm font-semibold text-gray-400">
                SERVICE
              </th>
              <th className="text-left p-4 text-sm font-semibold text-gray-400">
                VERSION
              </th>
              <th className="text-left p-4 text-sm font-semibold text-gray-400"></th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
    </>
  );
};

export default FingerprintTable;
