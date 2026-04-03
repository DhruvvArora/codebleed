import { useState, useRef } from "react";
import axios from "axios";
import HeroSection from "./components/HeroSection";
import GraphSection from "./components/GraphSection";
import ReportSection from "./components/ReportSection";
import "./index.css";

const API_BASE = "http://localhost:8000";

export default function App() {
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedPathId, setSelectedPathId] = useState(null);

  const graphRef = useRef(null);
  const reportRef = useRef(null);

  const handleScan = async (repoUrl) => {
    setLoading(true);
    setError(null);
    setScanData(null);
    setSelectedPathId(null);

    try {
      const { data } = await axios.post(`${API_BASE}/scan`, {
        repo_url: repoUrl,
        branch: "main",
        scan_mode: "full",
        include_commit_history: true,
        include_dependencies: true,
        include_secrets: true,
        include_endpoints: true,
      });

      setScanData(data);

      if (data.attack_paths?.length > 0) {
        setSelectedPathId(data.attack_paths[0].path_id);
      }

      setTimeout(() => {
        graphRef.current?.scrollIntoView({ behavior: "smooth" });
      }, 300);
    } catch (err) {
      setError(err?.response?.data?.detail || "Scan failed. Check the repo URL and try again.");
    } finally {
      setLoading(false);
    }
  };

  const handlePathSelect = (pathId) => {
    setSelectedPathId(pathId);
    graphRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const handleViewReport = () => {
    reportRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <div className="min-h-screen bg-light text-dark font-mono relative overflow-x-hidden">
      {/* Noise texture overlay */}
      <div
        className="fixed inset-0 pointer-events-none z-0 opacity-[0.035] bg-repeat"
        style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E")`,
          backgroundSize: "128px 128px",
        }}
      />

      {/* Header bar */}
      <header className="sticky top-0 z-[100] flex items-center justify-between px-8 py-[14px] bg-dark border-b border-accent">
        <span className="font-display text-xl text-light tracking-[-0.02em] flex items-center gap-2">
          <span className="text-accent text-base">▸</span> CodeBleed
        </span>
        <span className="text-[0.65rem] text-accent tracking-[0.12em] uppercase">
          Threat Intelligence · HackWithChicago 3.0
        </span>
      </header>

      {/* Section 1: Hero / Scan */}
      <section className="relative z-[1] min-h-screen flex flex-col">
        <HeroSection
          onScan={handleScan}
          loading={loading}
          error={error}
          scanData={scanData}
          selectedPathId={selectedPathId}
          onPathSelect={handlePathSelect}
          onViewReport={handleViewReport}
        />
      </section>

      {/* Section 2: Graph */}
      <section ref={graphRef} className="relative z-[1] min-h-screen flex flex-col bg-dark border-t-2 border-accent">
        <GraphSection
          scanData={scanData}
          selectedPathId={selectedPathId}
          onViewReport={handleViewReport}
        />
      </section>

      {/* Section 3: AI Report */}
      <section ref={reportRef} className="relative z-[1] min-h-screen flex flex-col bg-light border-t-2 border-dark">
        <ReportSection scanData={scanData} selectedPathId={selectedPathId} />
      </section>
    </div>
  );
}
