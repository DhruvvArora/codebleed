import { useState } from "react";

const SEVERITY_COLOR = {
  critical: "#e53e3e",
  high: "#dd6b20",
  medium: "#d69e2e",
  low: "#2d7a4f",
};

export default function HeroSection({
  onScan, loading, error, scanData, selectedPathId, onPathSelect, onViewReport,
}) {
  const [repoUrl, setRepoUrl] = useState("");

  const handleSubmit = () => { if (repoUrl.trim()) onScan(repoUrl.trim()); };
  const handleKey = (e) => { if (e.key === "Enter") handleSubmit(); };

  return (
    <div style={styles.root}>

      {/* ── Hero Section ── */}
      <div style={styles.heroSection}>
        <div style={styles.heroInner}>

          <div style={styles.eyebrow}>
            <span style={styles.eyebrowDot} />
            Threat Intelligence Platform
          </div>

          {/* Two lines, each pinned to one line */}
          <h1 style={styles.heroTitle}>
            <span style={styles.heroLine1}>Scan your {"<"}Codebase{"/>"}</span>
            <em style={styles.heroItalic}>Find the blast radius.</em>
          </h1>

          <p style={styles.heroSub}>
            AI-powered security analysis for LLM-assisted codebases.
            Uncover attack paths before someone else does.
          </p>

          {/* ── Input block ── */}
          <div style={styles.inputBlock}>
            <label style={styles.label}>Repository URL</label>
            <input
              style={styles.input}
              type="text"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              onKeyDown={handleKey}
              placeholder="add your repository url here..."
              disabled={loading}
            />
            <button
              style={{ ...styles.btn, ...(loading ? styles.btnDisabled : {}) }}
              onClick={handleSubmit}
              disabled={loading}
            >
              {loading ? "◌  Scanning…" : "▸  Run Scan"}
            </button>
            {error && <p style={styles.error}>{error}</p>}
          </div>

          {/* ── Feature grid — 1×4 ── */}
          <div style={styles.featureList}>
            {[
              ["◈", "Attack path analysis", "Trace dangerous paths from entry points to sensitive assets."],
              ["◎", "CVE matching", "Cross-reference deps against known vulnerability databases."],
              ["◆", "Secret detection", "Regex-based secrets scanner across commits and files."],
              ["▸", "AI reasoning", "GPT-4o generates prioritized, actionable fix reports."],
            ].map(([icon, title, desc], i, arr) => (
              <div
                key={title}
                style={{
                  ...styles.featureRow,
                  ...(i === arr.length - 1 ? { borderRight: "none", marginRight: 0, paddingRight: 0 } : {}),
                }}
              >
                <span style={styles.featureIcon}>{icon}</span>
                <div>
                  <div style={styles.featureTitle}>{title}</div>
                  <div style={styles.featureDesc}>{desc}</div>
                </div>
              </div>
            ))}
          </div>

        </div>
      </div>

      {/* ── Bottom panel ── */}
      <div style={styles.bottomPanel}>
        {!scanData && !loading && (
          <div style={styles.emptyRight}>
            <svg width="260" height="200" viewBox="0 0 260 200" fill="none" xmlns="http://www.w3.org/2000/svg">
              <circle cx="130" cy="40" r="18" stroke="#2d7a4f" strokeWidth="1.5" strokeDasharray="4 3" opacity="0.5" />
              <circle cx="50" cy="130" r="14" stroke="#d69e2e" strokeWidth="1.5" strokeDasharray="4 3" opacity="0.4" />
              <circle cx="210" cy="110" r="14" stroke="#dd6b20" strokeWidth="1.5" strokeDasharray="4 3" opacity="0.4" />
              <circle cx="100" cy="170" r="10" stroke="#e53e3e" strokeWidth="1.5" strokeDasharray="4 3" opacity="0.5" />
              <circle cx="175" cy="165" r="10" stroke="#805ad5" strokeWidth="1.5" strokeDasharray="4 3" opacity="0.4" />
              <line x1="130" y1="58" x2="60" y2="118" stroke="#1a1a18" strokeWidth="1" opacity="0.12" strokeDasharray="3 3" />
              <line x1="130" y1="58" x2="200" y2="98" stroke="#1a1a18" strokeWidth="1" opacity="0.12" strokeDasharray="3 3" />
              <line x1="60" y1="140" x2="102" y2="162" stroke="#e53e3e" strokeWidth="1.5" opacity="0.35" />
              <line x1="200" y1="122" x2="178" y2="157" stroke="#e53e3e" strokeWidth="1.5" opacity="0.35" />
              <line x1="112" y1="172" x2="167" y2="168" stroke="#1a1a18" strokeWidth="1" opacity="0.12" strokeDasharray="3 3" />
              <text x="118" y="45" fontSize="10" fill="#2d7a4f" opacity="0.8" fontFamily="monospace">repo</text>
              <text x="28" y="135" fontSize="9" fill="#d69e2e" opacity="0.8" fontFamily="monospace">dep</text>
              <text x="196" y="115" fontSize="9" fill="#dd6b20" opacity="0.8" fontFamily="monospace">ep</text>
              <text x="82" y="175" fontSize="9" fill="#e53e3e" opacity="0.8" fontFamily="monospace">secret</text>
              <text x="163" y="170" fontSize="9" fill="#805ad5" opacity="0.8" fontFamily="monospace">vuln</text>
            </svg>
            <p style={styles.emptyHeading}>Attack paths will appear here</p>
            <p style={styles.emptyDesc}>
              After scanning, Omen maps your repo as a threat graph and surfaces
              the most dangerous paths from entry points to sensitive assets.
            </p>
          </div>
        )}

        {loading && (
          <div style={styles.emptyRight}>
            <div style={styles.pulsingRing} />
            <p style={styles.emptyHeading}>Building threat graph…</p>
            <p style={styles.emptyDesc}>Fetching commits · Matching CVEs · Running AI analysis</p>
          </div>
        )}

        {scanData && (
          <div style={styles.pathsPanel}>
            <div style={styles.panelHeader}>
              <span style={styles.panelTitle}>Attack Paths</span>
              <span style={styles.panelCount}>{scanData.attack_paths.length} detected</span>
            </div>
            <div style={styles.pathsList}>
              {scanData.attack_paths.map((path) => (
                <PathCard
                  key={path.path_id}
                  path={path}
                  selected={path.path_id === selectedPathId}
                  onSelect={() => onPathSelect(path.path_id)}
                />
              ))}
            </div>
            <div style={styles.panelDivider} />
            <div style={styles.panelHeader}>
              <span style={styles.panelTitle}>Top Risks</span>
            </div>
            <div style={styles.risksList}>
              {scanData.top_risks.map((risk) => (
                <div key={risk.id} style={styles.riskRow}>
                  <div style={styles.riskLeft}>
                    <span style={{ ...styles.riskDot, backgroundColor: SEVERITY_COLOR[risk.severity] }} />
                    <span style={styles.riskTitle}>{risk.title}</span>
                  </div>
                  <span style={{ ...styles.riskScore, color: SEVERITY_COLOR[risk.severity] }}>
                    {risk.risk_score}
                  </span>
                </div>
              ))}
            </div>
            <button style={styles.reportBtn} onClick={onViewReport}>
              View Full AI Report ↓
            </button>
          </div>
        )}
      </div>

    </div>
  );
}

function PathCard({ path, selected, onSelect }) {
  return (
    <div style={{ ...styles.pathCard, ...(selected ? styles.pathCardSelected : {}) }} onClick={onSelect}>
      <div style={styles.pathCardTop}>
        <span style={{ ...styles.pathSev, color: SEVERITY_COLOR[path.severity] }}>
          {path.severity.toUpperCase()}
        </span>
        <span style={styles.pathScore}>{path.risk_score} / 100</span>
      </div>
      <p style={styles.pathSummary}>{path.summary}</p>
      <div style={styles.pathMeta}>
        {path.node_ids.length} nodes · {path.edge_ids.length} edges · {path.path_type.replace(/_/g, " ")}
      </div>
    </div>
  );
}

const styles = {
  root: {
    display: "flex",
    flexDirection: "column",
    minHeight: "calc(100vh - 53px)",
  },

  /* ── Hero ── */
  heroSection: {
    minHeight: "calc(100vh - 53px)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "60px 32px 48px",
    boxSizing: "border-box",
  },
  heroInner: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    textAlign: "center",
    gap: "28px",
    width: "100%",
    maxWidth: "1320px",
    margin: "0 auto",
  },

  eyebrow: {
    display: "flex", alignItems: "center", gap: "10px", marginTop: "20px", marginBottom: "30px",
    fontSize: "0.95rem", letterSpacing: "0.14em", textTransform: "uppercase", color: "#2d7a4f",
    border: "1px solid #2d7a4f",
    borderRadius: "30px",
    padding: "6px 12px"
  },
  eyebrowDot: {
    width: "7px", height: "7px", borderRadius: "50%",
    backgroundColor: "#2d7a4f", display: "inline-block", flexShrink: 0,
  },

  heroTitle: {
    fontFamily: "'Fraunces', serif",
    fontSize: "clamp(2rem, 3.5vw, 4rem)",
    fontWeight: 400,
    lineHeight: 1.06,
    letterSpacing: "-0.03em",
    color: "#1a1a18",
    margin: 0,
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: "4px",
    marginBottom: "20px",
  },

  heroLine1: {
    whiteSpace: "nowrap",
    display: "block",
  },

  heroItalic: {
    fontStyle: "italic",
    color: "#2d7a4f",
    whiteSpace: "nowrap",
    display: "block",
  },

  heroSub: {
    fontSize: "clamp(0.9rem, 1.3vw, 1.1rem)",
    color: "#6b6860",
    lineHeight: 1.7,
    maxWidth: "660px",
    marginBottom: "30px",
  },

  /* ── Input ── */
  inputBlock: {
    display: "flex",
    flexDirection: "column",
    gap: "12px",
    width: "100%",
    maxWidth: "580px",
  },
  label: {
    fontSize: "0.85rem", letterSpacing: "0.12em",
    textTransform: "uppercase", color: "#6b6860", textAlign: "left",
  },
  input: {
    width: "100%", padding: "15px 20px",
    fontFamily: "'DM Mono', monospace", fontSize: "0.9rem",
    backgroundColor: "#fff", border: "1px solid #d4cfc6", borderRadius: "5px",
    color: "#1a1a18", outline: "none", boxSizing: "border-box",
  },
  btn: {
    padding: "16px 0",
    fontFamily: "'DM Mono', monospace", fontSize: "0.95rem",
    backgroundColor: "#1a1a18", color: "#f5f2eb",
    border: "none", borderRadius: "5px", cursor: "pointer",
    letterSpacing: "0.06em", width: "100%",
  },
  btnDisabled: { opacity: 0.5, cursor: "not-allowed" },
  error: { fontSize: "0.82rem", color: "#e53e3e", margin: 0, textAlign: "left" },

  /* ── Feature grid — 1×4 ── */
  featureList: {
    display: "grid",
    gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
    width: "100%",
    maxWidth: "1400px",
    margin: "0 auto",
    padding: "0 8px",
    boxSizing: "border-box",
    textAlign: "left",
    borderTop: "1px solid #d4cfc6",
    paddingTop: "28px",
    marginTop: "16px",
  },
  featureRow: {
    display: "flex",
    gap: "12px",
    alignItems: "flex-start",
    padding: "0 24px",
    minWidth: 0,
    borderRight: "1px solid #d4cfc6",
  },
  featureIcon: {
    fontSize: "0.95rem",
    color: "#2d7a4f",
    flexShrink: 0,
    /* Nudge icon down to sit on the same baseline as the title's cap-height */
    marginTop: "3px",
    lineHeight: 1,
  },
  featureTitle: {
    fontSize: "0.95rem",
    color: "#1a1a18",
    fontWeight: 500,
    marginBottom: "5px",
    lineHeight: "1.5",
  },
  featureDesc: {
    fontSize: "0.82rem",
    color: "#6b6860",
    lineHeight: 1.55,
  },

  /* ── Bottom panel ── */
  bottomPanel: {
    borderTop: "1px solid #d4cfc6",
    width: "100%",
  },
  emptyRight: {
    display: "flex", flexDirection: "column",
    alignItems: "center", justifyContent: "center",
    padding: "72px 60px", textAlign: "center", gap: "20px",
  },
  emptyHeading: {
    fontFamily: "'Fraunces', serif", fontSize: "1.6rem",
    color: "#1a1a18", letterSpacing: "-0.02em", margin: 0,
  },
  emptyDesc: { fontSize: "0.85rem", color: "#6b6860", lineHeight: 1.7, maxWidth: "400px", margin: 0 },
  pulsingRing: {
    width: "52px", height: "52px", borderRadius: "50%",
    border: "2px solid #2d7a4f", animation: "spin 2s linear infinite", opacity: 0.5,
  },

  pathsPanel: {
    padding: "48px 64px",
    display: "flex", flexDirection: "column", gap: "20px",
    maxWidth: "960px", margin: "0 auto", width: "100%", boxSizing: "border-box",
  },
  panelHeader: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    paddingBottom: "14px", borderBottom: "1px solid #d4cfc6",
  },
  panelTitle: { fontSize: "0.7rem", letterSpacing: "0.14em", textTransform: "uppercase", color: "#1a1a18", fontWeight: 600 },
  panelCount: { fontSize: "0.7rem", color: "#6b6860" },
  pathsList: { display: "flex", flexDirection: "column", gap: "10px" },
  pathCard: {
    padding: "20px 22px", border: "1px solid #d4cfc6", borderRadius: "6px",
    cursor: "pointer", backgroundColor: "#fff",
    display: "flex", flexDirection: "column", gap: "8px",
    transition: "border-color 0.15s, box-shadow 0.15s",
  },
  pathCardSelected: { borderColor: "#2d7a4f", boxShadow: "0 0 0 3px rgba(45,122,79,0.1)" },
  pathCardTop: { display: "flex", justifyContent: "space-between", alignItems: "center" },
  pathSev: { fontSize: "0.65rem", letterSpacing: "0.1em", fontWeight: 700 },
  pathScore: { fontSize: "0.72rem", color: "#6b6860" },
  pathSummary: { fontSize: "0.85rem", color: "#1a1a18", margin: 0, lineHeight: 1.55 },
  pathMeta: { fontSize: "0.65rem", color: "#6b6860" },
  panelDivider: { borderTop: "1px solid #f0ece4" },
  risksList: { display: "flex", flexDirection: "column" },
  riskRow: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    padding: "14px 0", borderBottom: "1px solid #f0ece4",
  },
  riskLeft: { display: "flex", alignItems: "center", gap: "10px", flex: 1 },
  riskDot: { width: "8px", height: "8px", borderRadius: "50%", flexShrink: 0 },
  riskTitle: { fontSize: "0.85rem", color: "#1a1a18", lineHeight: 1.4 },
  riskScore: { fontFamily: "'Fraunces', serif", fontSize: "1.5rem", marginLeft: "20px", flexShrink: 0 },
  reportBtn: {
    alignSelf: "flex-start", marginTop: "8px", padding: "13px 28px",
    fontFamily: "'DM Mono', monospace", fontSize: "0.85rem",
    backgroundColor: "#1a1a18", color: "#f5f2eb",
    border: "none", borderRadius: "5px", cursor: "pointer", letterSpacing: "0.06em",
  },
};