import { BookMarked, FolderUp } from "lucide-react";

const TerminalCard = () => {
  return (
    <div>
      {/*Heading*/}
      <div className="items-center flex gap-2">
        <div className="text-gray-400">
          <BookMarked className="w-5" />
        </div>
        <h2 className="text-blue-500 text-lg">Repository</h2>
      </div>

      <div className="">
        {/*Terminal Window*/}
        <div className="p-4 ml-10">
          <div className="items-center justify-between flex rounded-t-lg bg-[#2f2f2f] py-3 px-4">
            <span className="font-md text-gray-500">Project Path</span>

            <div className="flex gap-1 rounded-md px-2 border border-transparent  hover:border-white cursor-pointer">
              <FolderUp className="w-4" />
              <span>Browse</span>
              <div />
            </div>
          </div>

          <div className="border-[#2f2f2f] border items-center bg-[#0d0d0d] p-4 rounded-b-lg">
            <div className="border border-[#2f2f2f] rounded-lg p-4">
              <span className="text-sm text-blue-300">
                Enter Source Code ZIP
              </span>
            </div>
          </div>
        </div>

        {/*Inputs And Options*/}
        <div className="flex items-center ml-24 gap-x-4">
          <span className="text-blue-300">Enter Application Name:</span>

          <input
            className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm"
            placeholder="My App"
          ></input>
        </div>

        <div className="flex items-center ml-24 gap-x-4 mt-4">
          <div className="gap-x-4 flex items-center">
            <span className="text-blue-300">Quick Scan</span>

            <input
              className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm"
              type="checkbox"
            ></input>
          </div>

          <div className="gap-x-4 flex items-center">
            <span className="text-blue-300">Demo Mode</span>

            <input
              className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm"
              type="checkbox"
            ></input>
          </div>
        </div>

        <div className="flex items-center ml-24 gap-x-4 mt-4">
          <span className="text-blue-300">Attack Mode (Stage 3):</span>

          <span>IP:</span>
          <input
            className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm w-[15vw]"
            placeholder="192.168.x.x"
          ></input>

          <span>Port:</span>
          <input
            className="bg-gray-800 opacity-50 rounded-lg p-2 text-sm w-[10vw]"
            placeholder="80"
          ></input>
        </div>
      </div>
    </div>
  );
};

export default TerminalCard;
