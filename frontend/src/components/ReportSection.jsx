import { styles, blockStyles, findingStyles } from "../styles/ReportSection.styles";
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
