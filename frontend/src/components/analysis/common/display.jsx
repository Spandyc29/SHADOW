export const emptyValue = "Not Available";
export const unavailableValue = "Not Available";

export function present(value) {
  if (
    value === null ||
    value === undefined ||
    value === "" ||
    (Array.isArray(value) && value.length === 0)
  ) {
    return unavailableValue;
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  return String(value);
}

export function presentOr(value, fallbackMessage = "Not Available") {
  if (
    value === null ||
    value === undefined ||
    value === "" ||
    value === "Not Available" ||
    (Array.isArray(value) && value.length === 0)
  ) {
    return fallbackMessage;
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  return String(value);
}


export function asList(value) {
  if (Array.isArray(value)) {
    return value;
  }

  if (value === null || value === undefined || value === "") {
    return [];
  }

  return [value];
}

const COUNTRY_MAP = {
  US: "🇺🇸 United States (US)",
  GB: "🇬🇧 United Kingdom (GB)",
  CA: "🇨🇦 Canada (CA)",
  AU: "🇦🇺 Australia (AU)",
  DE: "🇩🇪 Germany (DE)",
  FR: "🇫🇷 France (FR)",
  IN: "🇮🇳 India (IN)",
  JP: "🇯🇵 Japan (JP)",
  CN: "🇨🇳 China (CN)",
  NL: "🇳🇱 Netherlands (NL)",
  SE: "🇸🇪 Sweden (SE)",
  CH: "🇨🇭 Switzerland (CH)",
  ES: "🇪🇸 Spain (ES)",
  IT: "🇮🇹 Italy (IT)",
  BR: "🇧🇷 Brazil (BR)",
  RU: "🇷🇺 Russia (RU)",
  SG: "🇸🇬 Singapore (SG)",
  HK: "🇭🇰 Hong Kong (HK)",
  KR: "🇰🇷 South Korea (KR)",
  IE: "🇮🇪 Ireland (IE)",
  FI: "🇫🇮 Finland (FI)",
  NO: "🇳🇴 Norway (NO)",
  DK: "🇩🇰 Denmark (DK)",
  NZ: "🇳🇿 New Zealand (NZ)",
  ZA: "🇿🇦 South Africa (ZA)",
  MX: "🇲🇽 Mexico (MX)",
  PL: "🇵🇱 Poland (PL)",
  UA: "🇺🇦 Ukraine (UA)",
  RO: "🇷🇴 Romania (RO)",
  CZ: "🇨🇿 Czechia (CZ)",
  AT: "🇦🇹 Austria (AT)",
  BE: "🇧🇪 Belgium (BE)",
  PT: "🇵🇹 Portugal (PT)",
  GR: "🇬🇷 Greece (GR)",
  HU: "🇭🇺 Hungary (HU)",
  IL: "🇮🇱 Israel (IL)",
  AE: "🇦🇪 United Arab Emirates (AE)",
};

export function formatCountry(countryCode) {
  if (!countryCode || countryCode === emptyValue) {
    return unavailableValue;
  }

  const cleanCode = String(countryCode).trim().toUpperCase();
  if (COUNTRY_MAP[cleanCode]) {
    return COUNTRY_MAP[cleanCode];
  }

  return String(countryCode);
}

export function cleanStatusLabel(statusStr) {
  if (!statusStr) return "";

  let cleaned = String(statusStr);
  cleaned = cleaned.replace(/\s*\(?https?:\/\/[^\s\)]+\)?/gi, "");
  cleaned = cleaned.trim();
  return cleaned;
}

export function normalizeStatusList(statusInput) {
  const rawList = asList(statusInput);
  const seen = new Set();
  const result = [];

  for (const item of rawList) {
    const cleaned = cleanStatusLabel(item);
    if (!cleaned) continue;

    const lower = cleaned.toLowerCase();
    if (!seen.has(lower)) {
      seen.add(lower);
      result.push(cleaned);
    }
  }

  return result;
}

export function formatTimestamp(value) {
  if (value === null || value === undefined || value === "" || value === 0) {
    return unavailableValue;
  }

  const numeric = Number(value);
  let date;

  if (Number.isFinite(numeric)) {
    if (numeric <= 0) {
      return unavailableValue;
    }

    date = new Date(numeric * 1000);
  } else {
    date = new Date(value);
  }

  if (Number.isNaN(date.getTime()) || date.getUTCFullYear() <= 1970) {
    return unavailableValue;
  }

  return date.toLocaleString();
}

export function badgeClass(value) {
  const normalized = String(value || "").toLowerCase();

  if (["malicious", "critical", "high", "block", "quarantine", "poor"].some((item) => normalized.includes(item))) {
    return "border-red-400/40 bg-red-500/10 text-red-300 font-extrabold px-4 py-1.5 text-xs rounded-md shadow-sm whitespace-nowrap tracking-wide";
  }

  if (["suspicious", "medium", "review", "limited", "neutral", "unsigned"].some((item) => normalized.includes(item))) {
    return "border-amber-400/40 bg-amber-500/10 text-amber-300 font-extrabold px-4 py-1.5 text-xs rounded-md shadow-sm whitespace-nowrap tracking-wide";
  }

  if (
    [
      "clean",
      "low",
      "safe",
      "allow",
      "found",
      "high confidence",
      "signed",
      "excellent",
      "good",
    ].some((item) => normalized.includes(item))
  ) {
    return "border-emerald-400/40 bg-emerald-500/10 text-emerald-300 font-extrabold px-4 py-1.5 text-xs rounded-md shadow-sm whitespace-nowrap tracking-wide";
  }

  return "border-slate-700/60 bg-slate-800/80 text-slate-200 font-extrabold px-4 py-1.5 text-xs rounded-md shadow-sm whitespace-nowrap tracking-wide";
}

export function confidenceBadgeClass(value) {
  const normalized = String(value || "").toLowerCase();

  if (normalized.includes("high") || normalized.includes("strong")) {
    return "border-blue-400/40 bg-blue-500/10 text-blue-300 font-extrabold px-4 py-1.5 text-xs rounded-md shadow-sm whitespace-nowrap tracking-wide";
  }

  if (normalized.includes("medium") || normalized.includes("moderate")) {
    return "border-slate-400/40 bg-slate-500/10 text-slate-300 font-extrabold px-4 py-1.5 text-xs rounded-md shadow-sm whitespace-nowrap tracking-wide";
  }

  if (normalized.includes("low") || normalized.includes("unknown")) {
    return "border-slate-600 bg-slate-800 text-slate-400 font-extrabold px-4 py-1.5 text-xs rounded-md shadow-sm whitespace-nowrap tracking-wide";
  }

  return "border-slate-600 bg-slate-800 text-slate-400 font-extrabold px-4 py-1.5 text-xs rounded-md shadow-sm whitespace-nowrap tracking-wide";
}

export function progressWidth(value, max) {
  const numeric = Number(value);

  if (!Number.isFinite(numeric)) {
    return "0%";
  }

  return `${(Math.max(0, Math.min(numeric, max)) / max) * 100}%`;
}

export function riskProgressClass(value) {
  const normalized = String(value || "").toLowerCase();

  if (["malicious", "critical", "high", "block", "quarantine"].some((item) => normalized.includes(item))) {
    return "bg-red-400";
  }

  if (["suspicious", "medium", "review", "limited"].some((item) => normalized.includes(item))) {
    return "bg-amber-400";
  }

  if (["clean", "low", "safe", "allow", "found"].some((item) => normalized.includes(item))) {
    return "bg-emerald-400";
  }

  return "bg-slate-500";
}

export function JsonBlock({ value }) {
  if (value === null || value === undefined || value === "") {
    return <span className="text-slate-500">Not provided</span>;
  }

  if (typeof value !== "object") {
    return <span>{String(value)}</span>;
  }

  return (
    <pre className="max-h-72 overflow-auto rounded-md border border-slate-800 bg-slate-950/70 p-3 text-xs leading-relaxed text-slate-300">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}
