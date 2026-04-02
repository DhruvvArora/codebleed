import { useState } from "react";

const SEVERITY_COLOR = {
  critical: "#e53e3e",
  high:     "#dd6b20",
  medium:   "#d69e2e",
  low:      "#2d7a4f",
};

const SEVERITY_BG = {
  critical: "#fff5f5",
  high:     "#fffaf0",
  medium:   "#fffff0",
  low:      "#f0fff4",
};

export default function ReportSection({ scanData, selectedPathId }) {
  const [activeTab, setActiveTab] = useState("report");
  const [appliedFixes, setAppliedFixes] = useState(new Set());

  if (!scanData) {
    return (
      <div style={styles.empty}>
        <span style={styles.emptyIcon}>◎</span>
        <p style={styles.emptyTitle}>AI Report</p>
        <p style={styles.emptyText}>Run a scan to generate your threat intelligence report</p>
      </div>
    );
  }

  const { ai_report, findings, fix_candidates, summary } = scanData;
  const sev = ai_report.severity;

  const toggleFix = (fixId) => {
    setAppliedFixes((prev) => {
      const next = new Set(prev);
      next.has(fixId) ? next.delete(fixId) : next.add(fixId);
      return next;
    });
  };

  const totalReduction = fix_candidates
    .filter(f => appliedFixes.has(f.fix_id))
    .reduce((sum, f) => sum + f.estimated_risk_reduction, 0);
  const simulatedScore = Math.max(0, summary.risk_score - totalReduction);
  const cypherQuery = buildCypher(scanData, selectedPathId);

  return (
    <div style={styles.root}>
      {/* Big severity banner */}
      <div style={{ ...styles.banner, borderLeftColor: SEVERITY_COLOR[sev], backgroundColor: SEVERITY_BG[sev] }}>
        <div style={styles.bannerLeft}>
          <div style={{ ...styles.bannerSevLabel, color: SEVERITY_COLOR[sev] }}>
            {sev.toUpperCase()}
          </div>
          <h2 style={styles.bannerTitle}>{ai_report.threat_title}</h2>
          <p style={styles.bannerSummary}>{ai_report.executive_summary}</p>
        </div>
        <div style={styles.bannerRight}>
          <div style={styles.bigScore}>{summary.risk_score}</div>
          <div style={styles.bigScoreLabel}>risk score</div>
          <div style={styles.confScore}>{Math.round(ai_report.confidence * 100)}% confidence</div>
        </div>
      </div>

      {/* Tabs */}
      <div style={styles.tabBar}>
        {[["report", "AI Report"], ["fixes", `Fix Simulation (${fix_candidates.length})`], ["cypher", "Cypher Query"]].map(([id, label]) => (
          <button
            key={id}
            style={{ ...styles.tab, ...(activeTab === id ? styles.tabActive : {}) }}
            onClick={() => setActiveTab(id)}
          >
            {label}
          </button>
        ))}
      </div>

      <div style={styles.content}>

        {/* ── Report tab ── */}
        {activeTab === "report" && (
          <div style={styles.reportGrid}>
            <div style={styles.reportCol}>
              <Block title="Why It Matters">
                <p style={styles.prose}>{ai_report.why_it_matters}</p>
              </Block>
              <Block title="Key Findings">
                {ai_report.key_findings.map((f, i) => (
                  <div key={i} style={styles.findingItem}>
                    <span style={styles.findingBullet}>▸</span>
                    <span style={styles.findingText}>{f}</span>
                  </div>
                ))}
              </Block>
              <Block title="Recommended Fixes">
                {ai_report.recommended_fixes.map((f, i) => (
                  <div key={i} style={styles.findingItem}>
                    <span style={{ ...styles.findingBullet, color: "#2d7a4f" }}>✓</span>
                    <span style={styles.findingText}>{f}</span>
                  </div>
                ))}
              </Block>
            </div>

            <div style={styles.reportCol}>
              <Block title="Affected Files">
                {ai_report.affected_files.map(f => (
                  <div key={f} style={styles.fileRow}>
                    <span style={styles.fileIcon}>◫</span>
                    <span style={styles.fileName}>{f}</span>
                  </div>
                ))}
              </Block>

              <Block title="Secrets Detected">
                {findings.secrets.map(s => (
                  <FindingCard key={s.id} severity={s.severity}>
                    <div style={styles.fcTitle}>{s.type}</div>
                    <div style={styles.fcMeta}>{s.file}</div>
                    <div style={styles.fcMeta}>by {s.developer}</div>
                  </FindingCard>
                ))}
              </Block>

              <Block title="Vulnerabilities">
                {findings.vulnerabilities.map(v => (
                  <FindingCard key={v.id} severity={v.severity}>
                    <div style={styles.fcTitle}>{v.cve}</div>
                    <div style={styles.fcMeta}>{v.dependency}</div>
                    <div style={styles.fcMeta}>{v.affected_files.length} file(s) affected</div>
                  </FindingCard>
                ))}
              </Block>

              <Block title="Exposed Endpoints">
                {findings.endpoints.map(e => (
                  <FindingCard key={e.id} severity={e.severity}>
                    <div style={styles.fcTitle}>{e.method} {e.route}</div>
                    <div style={styles.fcMeta}>{e.file}</div>
                    {e.public_facing && <div style={{ ...styles.fcMeta, color: "#e53e3e" }}>public facing</div>}
                  </FindingCard>
                ))}
              </Block>
            </div>
          </div>
        )}

        {/* ── Fixes tab ── */}
        {activeTab === "fixes" && (
          <div style={styles.fixLayout}>
            <div style={styles.scoreMeter}>
              <div style={styles.scoreRow}>
                <div>
                  <div style={styles.scoreNum}>{summary.risk_score}</div>
                  <div style={styles.scoreNumLabel}>Current</div>
                </div>
                <div style={styles.scoreArrow}>→</div>
                <div>
                  <div style={{ ...styles.scoreNum, color: simulatedScore < 50 ? "#2d7a4f" : "#e53e3e" }}>
                    {simulatedScore}
                  </div>
                  <div style={styles.scoreNumLabel}>Simulated</div>
                </div>
                {appliedFixes.size > 0 && (
                  <div style={styles.reductionNote}>
                    ↓ {totalReduction} pts from {appliedFixes.size} fix(es)
                  </div>
                )}
              </div>
              <div style={styles.progressBar}>
                <div style={{
                  ...styles.progressFill,
                  width: `${simulatedScore}%`,
                  backgroundColor: simulatedScore < 50 ? "#2d7a4f" : simulatedScore < 75 ? "#d69e2e" : "#e53e3e",
                }} />
              </div>
            </div>

            <div style={styles.fixList}>
              {fix_candidates.sort((a, b) => a.priority - b.priority).map(fix => {
                const applied = appliedFixes.has(fix.fix_id);
                return (
                  <div key={fix.fix_id} style={{ ...styles.fixCard, ...(applied ? styles.fixCardApplied : {}) }}>
                    <div style={styles.fixTop}>
                      <div style={styles.fixTitleRow}>
                        <span style={styles.fixPriority}>P{fix.priority}</span>
                        <span style={styles.fixTitle}>{fix.title}</span>
                      </div>
                      <div style={styles.fixMeta}>
                        <span style={styles.fixReduction}>−{fix.estimated_risk_reduction} pts</span>
                        <button
                          style={{ ...styles.fixBtn, ...(applied ? styles.fixBtnApplied : {}) }}
                          onClick={() => toggleFix(fix.fix_id)}
                        >
                          {applied ? "✓ Applied" : "Apply Fix"}
                        </button>
                      </div>
                    </div>
                    <p style={styles.fixDesc}>{fix.description}</p>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ── Cypher tab ── */}
        {activeTab === "cypher" && (
          <div style={styles.cypherBlock}>
            <div style={styles.cypherHeader}>
              <span style={styles.cypherLabel}>Generated Cypher Query</span>
              <button style={styles.copyBtn} onClick={() => navigator.clipboard.writeText(cypherQuery)}>
                Copy to clipboard
              </button>
            </div>
            <pre style={styles.cypherCode}>{cypherQuery}</pre>
            <p style={styles.cypherNote}>
              Paste this into Neo4j Browser to inspect the attack path in your graph database.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function Block({ title, children }) {
  return (
    <div style={blockStyles.root}>
      <div style={blockStyles.title}>{title}</div>
      <div style={blockStyles.body}>{children}</div>
    </div>
  );
}

function FindingCard({ severity, children }) {
  return (
    <div style={{ ...findingStyles.card, borderLeftColor: SEVERITY_COLOR[severity] }}>
      {children}
    </div>
  );
}

function buildCypher(scanData, selectedPathId) {
  const path = scanData.attack_paths.find(p => p.path_id === selectedPathId);
  if (!path) return `// No attack path selected\nMATCH (n) RETURN n LIMIT 50;`;
  const nodeIds = path.node_ids.map(id => `'${id}'`).join(", ");
  return `// Attack Path: ${path.path_id}
// ${path.summary}
// Severity: ${path.severity} | Risk Score: ${path.risk_score}

MATCH p = (entry)-[*]->(target)
WHERE entry.id IN [${nodeIds}]
  AND target.id = '${path.target_node_id}'
RETURN p;

// Inspect individual nodes
MATCH (n)
WHERE n.id IN [${nodeIds}]
RETURN n.id, n.name, n.label, n.severity, n.risk_score
ORDER BY n.risk_score DESC;`;
}

const styles = {
  root: { display: "flex", flexDirection: "column", minHeight: "calc(100vh - 53px)" },
  empty: {
    display: "flex", flexDirection: "column", alignItems: "center",
    justifyContent: "center", minHeight: "calc(100vh - 53px)", gap: "16px",
  },
  emptyIcon: { fontSize: "2.5rem", color: "#1a1a18", opacity: 0.2 },
  emptyTitle: { fontFamily: "'Fraunces', serif", fontSize: "1.6rem", color: "#1a1a18", opacity: 0.3, margin: 0 },
  emptyText: { fontSize: "0.78rem", color: "#6b6860", margin: 0 },

  banner: {
    display: "flex", alignItems: "flex-start", justifyContent: "space-between",
    padding: "40px 56px", borderLeft: "5px solid", flexWrap: "wrap", gap: "24px",
  },
  bannerLeft: { display: "flex", flexDirection: "column", gap: "10px", flex: 1 },
  bannerSevLabel: { fontSize: "0.62rem", letterSpacing: "0.16em", fontWeight: 700 },
  bannerTitle: {
    fontFamily: "'Fraunces', serif", fontSize: "clamp(1.4rem, 2.5vw, 2rem)",
    fontWeight: 400, letterSpacing: "-0.02em", color: "#1a1a18", margin: 0, lineHeight: 1.2,
  },
  bannerSummary: { fontSize: "0.85rem", color: "#6b6860", lineHeight: 1.65, margin: 0, maxWidth: "520px" },
  bannerRight: { display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "4px", flexShrink: 0 },
  bigScore: {
    fontFamily: "'Fraunces', serif", fontSize: "5rem",
    lineHeight: 1, color: "#1a1a18", letterSpacing: "-0.05em",
  },
  bigScoreLabel: { fontSize: "0.62rem", letterSpacing: "0.12em", textTransform: "uppercase", color: "#6b6860" },
  confScore: { fontSize: "0.68rem", color: "#6b6860", marginTop: "4px" },

  tabBar: { display: "flex", borderBottom: "1px solid #d4cfc6", padding: "0 56px" },
  tab: {
    padding: "14px 22px", fontFamily: "'DM Mono', monospace", fontSize: "0.75rem",
    backgroundColor: "transparent", color: "#6b6860",
    border: "none", borderBottom: "2px solid transparent",
    cursor: "pointer", letterSpacing: "0.04em",
  },
  tabActive: { color: "#1a1a18", borderBottomColor: "#1a1a18" },

  content: { flex: 1, padding: "48px 56px" },

  reportGrid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "56px" },
  reportCol: { display: "flex", flexDirection: "column", gap: "36px" },

  prose: { fontSize: "0.85rem", color: "#3a3a38", lineHeight: 1.75, margin: 0 },
  findingItem: { display: "flex", gap: "10px", marginBottom: "8px" },
  findingBullet: { color: "#dd6b20", flexShrink: 0, marginTop: "1px" },
  findingText: { fontSize: "0.82rem", color: "#3a3a38", lineHeight: 1.55 },

  fileRow: {
    display: "flex", alignItems: "center", gap: "10px",
    padding: "8px 12px", backgroundColor: "#f0ece4", borderRadius: "4px", marginBottom: "6px",
  },
  fileIcon: { fontSize: "0.7rem", color: "#6b6860" },
  fileName: { fontSize: "0.75rem", fontFamily: "'DM Mono', monospace", color: "#1a1a18" },

  fcTitle: { fontSize: "0.82rem", fontWeight: 600, color: "#1a1a18", marginBottom: "4px" },
  fcMeta: { fontSize: "0.7rem", color: "#6b6860" },

  // Fixes
  fixLayout: { display: "flex", flexDirection: "column", gap: "36px", maxWidth: "720px" },
  scoreMeter: { padding: "28px", border: "1px solid #d4cfc6", borderRadius: "8px", backgroundColor: "#fff", display: "flex", flexDirection: "column", gap: "16px" },
  scoreRow: { display: "flex", alignItems: "center", gap: "24px" },
  scoreNum: { fontFamily: "'Fraunces', serif", fontSize: "3.5rem", lineHeight: 1, color: "#1a1a18", letterSpacing: "-0.04em" },
  scoreNumLabel: { fontSize: "0.6rem", letterSpacing: "0.1em", textTransform: "uppercase", color: "#6b6860", marginTop: "4px" },
  scoreArrow: { fontSize: "1.4rem", color: "#6b6860" },
  reductionNote: { fontSize: "0.72rem", color: "#2d7a4f", marginLeft: "auto" },
  progressBar: { height: "6px", backgroundColor: "#f0ece4", borderRadius: "3px", overflow: "hidden" },
  progressFill: { height: "100%", borderRadius: "3px", transition: "width 0.4s ease, background-color 0.4s ease" },

  fixList: { display: "flex", flexDirection: "column", gap: "12px" },
  fixCard: {
    padding: "20px 22px", border: "1px solid #d4cfc6", borderRadius: "6px",
    backgroundColor: "#fff", display: "flex", flexDirection: "column", gap: "8px",
    transition: "border-color 0.15s, box-shadow 0.15s",
  },
  fixCardApplied: { borderColor: "#2d7a4f", boxShadow: "0 0 0 3px rgba(45,122,79,0.1)" },
  fixTop: { display: "flex", alignItems: "center", justifyContent: "space-between" },
  fixTitleRow: { display: "flex", alignItems: "center", gap: "10px" },
  fixPriority: { fontSize: "0.6rem", padding: "2px 7px", backgroundColor: "#f0ece4", borderRadius: "3px", color: "#6b6860" },
  fixTitle: { fontSize: "0.85rem", fontWeight: 600, color: "#1a1a18" },
  fixMeta: { display: "flex", alignItems: "center", gap: "14px" },
  fixReduction: { fontSize: "0.75rem", color: "#2d7a4f", fontWeight: 600 },
  fixBtn: {
    padding: "7px 16px", fontFamily: "'DM Mono', monospace", fontSize: "0.7rem",
    backgroundColor: "transparent", color: "#1a1a18",
    border: "1px solid #d4cfc6", borderRadius: "4px", cursor: "pointer",
  },
  fixBtnApplied: { backgroundColor: "#2d7a4f", color: "#fff", borderColor: "#2d7a4f" },
  fixDesc: { fontSize: "0.78rem", color: "#6b6860", margin: 0, lineHeight: 1.55 },

  // Cypher
  cypherBlock: { display: "flex", flexDirection: "column", gap: "16px", maxWidth: "800px" },
  cypherHeader: { display: "flex", alignItems: "center", justifyContent: "space-between" },
  cypherLabel: { fontSize: "0.65rem", letterSpacing: "0.12em", textTransform: "uppercase", color: "#6b6860" },
  copyBtn: {
    padding: "7px 16px", fontFamily: "'DM Mono', monospace", fontSize: "0.7rem",
    backgroundColor: "transparent", color: "#1a1a18",
    border: "1px solid #d4cfc6", borderRadius: "4px", cursor: "pointer",
  },
  cypherCode: {
    backgroundColor: "#1a1a18", color: "#2d7a4f", padding: "28px",
    borderRadius: "6px", fontFamily: "'DM Mono', monospace",
    fontSize: "0.78rem", lineHeight: 1.85, overflowX: "auto", margin: 0, whiteSpace: "pre",
  },
  cypherNote: { fontSize: "0.73rem", color: "#6b6860", margin: 0 },
};

const blockStyles = {
  root: { display: "flex", flexDirection: "column", gap: "14px" },
  title: {
    fontSize: "0.62rem", letterSpacing: "0.14em", textTransform: "uppercase",
    color: "#6b6860", paddingBottom: "10px", borderBottom: "1px solid #d4cfc6",
  },
  body: { display: "flex", flexDirection: "column" },
};

const findingStyles = {
  card: {
    padding: "12px 16px", borderLeft: "3px solid",
    backgroundColor: "#fafaf8", borderRadius: "0 5px 5px 0", marginBottom: "8px",
  },
};
