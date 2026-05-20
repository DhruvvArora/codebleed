import { useState, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import GraphSection from "../components/GraphSection";
import ReportSection from "../components/ReportSection";
import styles from "../styles/ResultsPage.module.css";

export default function ResultsPage() {
  const { state } = useLocation();
  const navigate = useNavigate();
  const reportRef = useRef(null);

  const [selectedPathId, setSelectedPathId] = useState(
    state?.scanData?.attack_paths?.[0]?.path_id ?? null
  );

  // Guard: if no scan data, redirect home
  if (!state?.scanData) {
    return (
      <div className={styles.empty}>
        <p className={styles.emptyText}>No scan data found.</p>
        <button className={styles.backBtn} onClick={() => navigate("/")}>
          ← Run a scan
        </button>
      </div>
    );
  }

  const { scanData, repoUrl } = state;

  const handlePathSelect = (pathId) => {
    setSelectedPathId(pathId);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleViewReport = () => {
    reportRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <div className={styles.root}>
      {/* Back bar */}
      <div className={styles.backBar}>
        <button className={styles.backBtn} onClick={() => navigate("/")}>
          ← New scan
        </button>
        <span className={styles.repoLabel}>{repoUrl}</span>
        <div className={styles.summaryPills}>
          <span className={styles.pill}>
            {scanData.summary.attack_paths_found} paths
          </span>
          <span className={styles.pill}>
            {scanData.summary.secrets_found} secrets
          </span>
          <span className={styles.pill}>
            {scanData.summary.vulnerabilities_found} vulns
          </span>
          <span className={`${styles.pill} ${styles.pillScore}`}>
            risk {scanData.summary.risk_score}
          </span>
        </div>
      </div>

      {/* Graph section */}
      <section className={styles.graphSection}>
        <GraphSection
          scanData={scanData}
          selectedPathId={selectedPathId}
          onViewReport={handleViewReport}
        />
      </section>

      {/* Report section */}
      <section ref={reportRef} className={styles.reportSection}>
        <ReportSection
          scanData={scanData}
          selectedPathId={selectedPathId}
          onPathSelect={handlePathSelect}
        />
      </section>
    </div>
  );
}
