import { MapPin } from "lucide-react";
import { formatCountry, presentOr } from "../common/display";

function GeolocationCard({ result }) {
  const ipInfo = result?.ip_info || {};

  const rawCountry = ipInfo.country || result?.country;
  const countryFormatted = rawCountry
    ? formatCountry(rawCountry)
    : "Provider did not return country information.";

  const region = presentOr(ipInfo.region || result?.region, "Provider did not return region information.");
  const city = presentOr(ipInfo.city || result?.city, "Provider did not return city information.");
  const continent = presentOr(ipInfo.continent || result?.continent, "Provider did not return continent information.");

  const items = [
    {
      label: "Country",
      value: countryFormatted,
      isMuted: countryFormatted.startsWith("Provider"),
    },
    {
      label: "Region",
      value: region,
      isMuted: region.startsWith("Provider"),
    },
    {
      label: "City",
      value: city,
      isMuted: city.startsWith("Provider"),
    },
    {
      label: "Continent",
      value: continent,
      isMuted: continent.startsWith("Provider"),
    },
  ];

  return (
    <section className="analysis-card relative overflow-hidden rounded-2xl border border-slate-700/80 bg-[#0d1017] shadow-xl transition-all duration-300 hover:border-emerald-500/50 hover:shadow-2xl hover:shadow-emerald-950/20">
      {/* Top Emerald Accent Bar */}
      <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500" />

      {/* Card Header */}
      <div className="flex items-center gap-4 border-b border-slate-800/80 pb-5">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 shadow-inner">
          <MapPin className="h-6 w-6" />
        </div>
        <div>
          <p className="text-sm font-semibold uppercase tracking-wider text-emerald-400">
            Geolocation
          </p>
          <h2 className="mt-1 text-2xl sm:text-3xl font-extrabold font-mono text-white tracking-tight">
            Geographic Origin
          </h2>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {items.map((item) => (
          <div key={item.label} className="rounded-xl border border-slate-800/80 bg-[#07090e] p-5 transition-colors hover:border-slate-700">
            <p className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-slate-400">
              {item.label}
            </p>
            <div className={`mt-2.5 break-words text-base sm:text-lg font-semibold ${item.isMuted ? "text-slate-400 font-normal text-sm sm:text-base" : "text-slate-100"}`}>
              {item.value}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

export default GeolocationCard;
