import Radar from "../components/Radar";
import {
  backlog,
  exploit,
  target,
  attack,
  generation,
  discovery,
} from "../helpers/assetExport";

const LandingPage: React.FC = () => {
  const cards = [
    { id: 1, img: backlog },
    { id: 2, img: exploit },
    { id: 3, img: target },
    { id: 4, img: attack },
    { id: 5, img: generation },
    { id: 6, img: discovery },
  ];

  return (
    <>
      {/* Hero Section */}
      <section className="relative flex flex-col items-center justify-center pt-8">
        {/* Radar Section */}
        <div className="relative z-10 mb-12">
          <Radar />
        </div>
      </section>

      {/* Hero Title and Supporting Text */}
      <div className="relative z-10 text-center max-w-5xl mx-auto px-4">
        <h1 className="text-6xl md:text-7xl mb-6 tracking-tight">
          <span className="text-white">From Detection to</span>
          <br />
          <span className="text-white">Exploitation — Instantly.</span>
        </h1>

        <p className="text-xl md:text-2xl text-gray-400 font-light">
          Precision scanning with automated exploit modeling for red-team
          operations.
        </p>
      </div>

      {/* Features Section */}
      <section className="relative px-4 mt-8 z-10">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
            {cards.map((card) => (
              <div
                key={card.id}
                className="relative rounded-lg overflow-hidden group"
              >
                <img
                  src={card.img}
                  alt={`Feature ${card.id}`}
                  className="w-full h-full"
                />
              </div>
            ))}
          </div>
        </div>
      </section>
    </>
  );
};

export default LandingPage;
