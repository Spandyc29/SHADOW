import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import StatCard from "../components/StatCard";
import ThreatActivityChart from "../components/dashboard/ThreatActivityChart";
import TopThreatCategoriesChart from "../components/dashboard/TopThreatCategoriesChart";
import ScanActivityWidget from "../components/dashboard/ScanActivityWidget";
import RecentScansTable from "../components/RecentScansTable";
import { getDashboardStats } from "../services/api";
import "../styles/dashboard.css";

function Dashboard() {
  const { user, isGuest } = useAuth();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const greetingName =
    user?.user_metadata?.display_name ||
    (user?.email ? user.email.split("@")[0] : isGuest ? "Guest" : "Operative");

  useEffect(() => {
    getDashboardStats()
      .then((res) => {
        setStats(res.data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Dashboard stats error:", err);
        setError("Failed to load stats");
        setLoading(false);
      });
  }, []);

  if (loading) return <div className="dashboard-content p-6 text-slate-400 font-medium">Loading Dashboard...</div>;
  if (error) return <div className="dashboard-content p-6 text-red-400 font-medium">{error}</div>;

  return (
    <div className="dashboard-content flex flex-col gap-6">
      {/* HEADER */}
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <p>Welcome back, {greetingName} 👋</p>
      </div>

      {/* ROW 1: TOP 5 STAT CARDS */}
      <div className="stats-grid">
        <StatCard type="total_scans" stat={stats?.total_scans} value={stats?.total_scans} />
        <StatCard type="clean" stat={stats?.clean} value={stats?.clean_files} />
        <StatCard type="suspicious" stat={stats?.suspicious} />
        <StatCard type="threats" stat={stats?.threats} value={stats?.threats_detected} />
        <StatCard type="not_found" stat={stats?.not_found} value={stats?.not_found_count} />
      </div>

      {/* ROW 2: THREAT ACTIVITY LINE CHART */}
      <div>
        <ThreatActivityChart stats={stats} />
      </div>

      {/* ROW 3: SCAN ACTIVITY + TOP THREAT CATEGORIES */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ScanActivityWidget stats={stats} />
        <TopThreatCategoriesChart stats={stats} />
      </div>

      {/* ROW 4: RECENT SCANS TABLE */}
      <div>
        <RecentScansTable scans={stats?.recent_scans} />
      </div>
    </div>
  );
}

export default Dashboard;