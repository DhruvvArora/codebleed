import { useState, useRef } from "react";
import axios from "axios";
import HeroSection from "./components/HeroSection";
import GraphSection from "./components/GraphSection";
import ReportSection from "./components/ReportSection";

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

      // Auto-select first attack path
      if (data.attack_paths?.length > 0) {
        setSelectedPathId(data.attack_paths[0].path_id);
      }

      // Scroll to graph after scan
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
    <div style={styles.root}>
      {/* ── Noise texture overlay ── */}
      <div style={styles.noise} />

      {/* ── Header bar ── */}
      <header style={styles.header}>
        <span style={styles.logo}>
          <span style={styles.logoDot}>▸</span> CodeBleed
        </span>
        <span style={styles.headerTag}>Threat Intelligence · HackWithChicago 3.0</span>
      </header>

      {/* ── Section 1: Hero / Scan ── */}
      <section style={styles.section}>
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

      {/* ── Section 2: Graph ── */}
      <section ref={graphRef} style={{ ...styles.section, ...styles.graphSection }}>
        <GraphSection
          scanData={scanData}
          selectedPathId={selectedPathId}
          onViewReport={handleViewReport}
        />
      </section>

      {/* ── Section 3: AI Report ── */}
      <section ref={reportRef} style={{ ...styles.section, ...styles.reportSection }}>
        <ReportSection scanData={scanData} selectedPathId={selectedPathId} />
      </section>
    </div>
  );
}

const styles = {
  root: {
    minHeight: "100vh",
    backgroundColor: "#f5f2eb",
    color: "#1a1a18",
    fontFamily: "'DM Mono', monospace",
    position: "relative",
    overflowX: "hidden",
  },
  noise: {
    position: "fixed",
    inset: 0,
    pointerEvents: "none",
    zIndex: 0,
    opacity: 0.035,
    backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E")`,
    backgroundRepeat: "repeat",
    backgroundSize: "128px 128px",
  },
  header: {
    position: "sticky",
    top: 0,
    zIndex: 100,
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "14px 32px",
    backgroundColor: "#1a1a18",
    borderBottom: "1px solid #2d7a4f",
  },
  logo: {
    fontFamily: "'Fraunces', serif",
    fontSize: "1.25rem",
    color: "#f5f2eb",
    letterSpacing: "-0.02em",
    display: "flex",
    alignItems: "center",
    gap: "8px",
  },
  logoDot: {
    color: "#2d7a4f",
    fontSize: "1rem",
  },
  headerTag: {
    fontSize: "0.65rem",
    color: "#2d7a4f",
    letterSpacing: "0.12em",
    textTransform: "uppercase",
  },
  section: {
    position: "relative",
    zIndex: 1,
    minHeight: "100vh",
    display: "flex",
    flexDirection: "column",
  },
  graphSection: {
    backgroundColor: "#1a1a18",
    borderTop: "2px solid #2d7a4f",
  },
  reportSection: {
    backgroundColor: "#f5f2eb",
    borderTop: "2px solid #1a1a18",
  },
};
