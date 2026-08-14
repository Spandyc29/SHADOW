import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Navbar from "./Navbar";
import ShadowCharacter from "./shadow/ShadowCharacter";
import "../styles/layout.css";

function Layout() {
  return (
    <div className="layout">
      <Sidebar />

      <main className="main-content">
        <Navbar />
        <Outlet />
      </main>

      {/* SHADOW AI Companion — Production Vector Mascot */}
      <ShadowCharacter />
    </div>
  );
}

export default Layout;