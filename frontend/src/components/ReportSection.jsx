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
      <div className="flex flex-col items-center justify-center min-h-[calc(100vh-53px)] gap-4">
        <span className="text-[2.5rem] text-dark opacity-20">◎</span>
        <p className="font-display text-[1.6rem] text-dark opacity-30 m-0">AI Report</p>
        <p className="text-[0.78rem] text-muted m-0">Run a scan to generate your threat intelligence report</p>
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
    <div className="flex flex-col min-h-[calc(100vh-53px)]">

      {/* Severity banner */}
      <div
        className="flex items-start justify-between px-14 py-10 border-l-[5px] flex-wrap gap-6"
        style={{
          borderLeftColor: SEVERITY_COLOR[sev],
          backgroundColor: SEVERITY_BG[sev],
        }}
      >
        <div className="flex flex-col gap-[10px] flex-1">
          <div className="text-[0.62rem] tracking-[0.16em] font-bold" style={{ color: SEVERITY_COLOR[sev] }}>
            {sev.toUpperCase()}
          </div>
          <h2 className="font-display text-[clamp(1.4rem,2.5vw,2rem)] font-normal tracking-[-0.02em] text-dark m-0 leading-[1.2]">
            {ai_report.threat_title}
          </h2>
          <p className="text-[0.85rem] text-muted leading-[1.65] m-0 max-w-[520px]">
            {ai_report.executive_summary}
          </p>
        </div>
        <div className="flex flex-col items-end gap-1 shrink-0">
          <div className="font-display text-[5rem] leading-none text-dark tracking-[-0.05em]">
            {summary.risk_score}
          </div>
          <div className="text-[0.62rem] tracking-[0.12em] uppercase text-muted">risk score</div>
          <div className="text-[0.68rem] text-muted mt-1">
            {Math.round(ai_report.confidence * 100)}% confidence
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border px-14">
        {[["report", "AI Report"], ["fixes", `Fix Simulation (${fix_candidates.length})`], ["cypher", "Cypher Query"]].map(([id, label]) => (
          <button
            key={id}
            className={`px-[22px] py-[14px] font-mono text-[0.75rem] bg-transparent border-none border-b-2 cursor-pointer tracking-[0.04em] transition-colors${activeTab === id ? " text-dark border-b-dark border-dark" : " text-muted border-b-transparent"}`}
            style={{ borderBottomWidth: "2px", borderBottomStyle: "solid", borderBottomColor: activeTab === id ? "#1a1a18" : "transparent" }}
            onClick={() => setActiveTab(id)}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="flex-1 px-14 py-12">

        {/* Report tab */}
        {activeTab === "report" && (
          <div className="grid grid-cols-2 gap-14">
            <div className="flex flex-col gap-9">
              <Block title="Why It Matters">
                <p className="text-[0.85rem] text-[#3a3a38] leading-[1.75] m-0">{ai_report.why_it_matters}</p>
              </Block>
              <Block title="Key Findings">
                {ai_report.key_findings.map((f, i) => (
                  <div key={i} className="flex gap-[10px] mb-2">
                    <span className="text-high shrink-0 mt-[1px]">▸</span>
                    <span className="text-[0.82rem] text-[#3a3a38] leading-[1.55]">{f}</span>
                  </div>
                ))}
              </Block>
              <Block title="Recommended Fixes">
                {ai_report.recommended_fixes.map((f, i) => (
                  <div key={i} className="flex gap-[10px] mb-2">
                    <span className="text-accent shrink-0 mt-[1px]">✓</span>
                    <span className="text-[0.82rem] text-[#3a3a38] leading-[1.55]">{f}</span>
                  </div>
                ))}
              </Block>
            </div>

            <div className="flex flex-col gap-9">
              <Block title="Affected Files">
                {ai_report.affected_files.map(f => (
                  <div key={f} className="flex items-center gap-[10px] px-3 py-2 bg-subtle rounded-[4px] mb-[6px]">
                    <span className="text-[0.7rem] text-muted">◫</span>
                    <span className="text-[0.75rem] font-mono text-dark">{f}</span>
                  </div>
                ))}
              </Block>

              <Block title="Secrets Detected">
                {findings.secrets.map(s => (
                  <FindingCard key={s.id} severity={s.severity}>
                    <div className="text-[0.82rem] font-semibold text-dark mb-1">{s.type}</div>
                    <div className="text-[0.7rem] text-muted">{s.file}</div>
                    <div className="text-[0.7rem] text-muted">by {s.developer}</div>
                  </FindingCard>
                ))}
              </Block>

              <Block title="Vulnerabilities">
                {findings.vulnerabilities.map(v => (
                  <FindingCard key={v.id} severity={v.severity}>
                    <div className="text-[0.82rem] font-semibold text-dark mb-1">{v.cve}</div>
                    <div className="text-[0.7rem] text-muted">{v.dependency}</div>
                    <div className="text-[0.7rem] text-muted">{v.affected_files.length} file(s) affected</div>
                  </FindingCard>
                ))}
              </Block>

              <Block title="Exposed Endpoints">
                {findings.endpoints.map(e => (
                  <FindingCard key={e.id} severity={e.severity}>
                    <div className="text-[0.82rem] font-semibold text-dark mb-1">{e.method} {e.route}</div>
                    <div className="text-[0.7rem] text-muted">{e.file}</div>
                    {e.public_facing && <div className="text-[0.7rem] text-critical">public facing</div>}
                  </FindingCard>
                ))}
              </Block>
            </div>
          </div>
        )}

        {/* Fixes tab */}
        {activeTab === "fixes" && (
          <div className="flex flex-col gap-9 max-w-[720px]">
            <div className="px-7 py-7 border border-border rounded-[8px] bg-white flex flex-col gap-4">
              <div className="flex items-center gap-6">
                <div>
                  <div className="font-display text-[3.5rem] leading-none text-dark tracking-[-0.04em]">
                    {summary.risk_score}
                  </div>
                  <div className="text-[0.6rem] tracking-[0.1em] uppercase text-muted mt-1">Current</div>
                </div>
                <div className="text-[1.4rem] text-muted">→</div>
                <div>
                  <div
                    className="font-display text-[3.5rem] leading-none tracking-[-0.04em]"
                    style={{ color: simulatedScore < 50 ? "#2d7a4f" : "#e53e3e" }}
                  >
                    {simulatedScore}
                  </div>
                  <div className="text-[0.6rem] tracking-[0.1em] uppercase text-muted mt-1">Simulated</div>
                </div>
                {appliedFixes.size > 0 && (
                  <div className="text-[0.72rem] text-accent ml-auto">
                    ↓ {totalReduction} pts from {appliedFixes.size} fix(es)
                  </div>
                )}
              </div>
              <div className="h-[6px] bg-subtle rounded-[3px] overflow-hidden">
                <div
                  className="h-full rounded-[3px] transition-[width,background-color] duration-400"
                  style={{
                    width: `${simulatedScore}%`,
                    backgroundColor: simulatedScore < 50 ? "#2d7a4f" : simulatedScore < 75 ? "#d69e2e" : "#e53e3e",
                  }}
                />
              </div>
            </div>

            <div className="flex flex-col gap-3">
              {fix_candidates.sort((a, b) => a.priority - b.priority).map(fix => {
                const applied = appliedFixes.has(fix.fix_id);
                return (
                  <div
                    key={fix.fix_id}
                    className={`px-[22px] py-5 border rounded-[6px] bg-white flex flex-col gap-2 transition-[border-color,box-shadow] duration-150${applied ? " border-accent shadow-[0_0_0_3px_rgba(45,122,79,0.1)]" : " border-border"}`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-[10px]">
                        <span className="text-[0.6rem] px-[7px] py-[2px] bg-subtle rounded-[3px] text-muted">
                          P{fix.priority}
                        </span>
                        <span className="text-[0.85rem] font-semibold text-dark">{fix.title}</span>
                      </div>
                      <div className="flex items-center gap-[14px]">
                        <span className="text-[0.75rem] text-accent font-semibold">−{fix.estimated_risk_reduction} pts</span>
                        <button
                          className={`px-4 py-[7px] font-mono text-[0.7rem] border rounded-[4px] cursor-pointer${applied ? " bg-accent text-white border-accent" : " bg-transparent text-dark border-border"}`}
                          onClick={() => toggleFix(fix.fix_id)}
                        >
                          {applied ? "✓ Applied" : "Apply Fix"}
                        </button>
                      </div>
                    </div>
                    <p className="text-[0.78rem] text-muted m-0 leading-[1.55]">{fix.description}</p>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Cypher tab */}
        {activeTab === "cypher" && (
          <div className="flex flex-col gap-4 max-w-[800px]">
            <div className="flex items-center justify-between">
              <span className="text-[0.65rem] tracking-[0.12em] uppercase text-muted">Generated Cypher Query</span>
              <button
                className="px-4 py-[7px] font-mono text-[0.7rem] bg-transparent text-dark border border-border rounded-[4px] cursor-pointer"
                onClick={() => navigator.clipboard.writeText(cypherQuery)}
              >
                Copy to clipboard
              </button>
            </div>
            <pre className="bg-dark text-accent px-7 py-7 rounded-[6px] font-mono text-[0.78rem] leading-[1.85] overflow-x-auto m-0 whitespace-pre">
              {cypherQuery}
            </pre>
            <p className="text-[0.73rem] text-muted m-0">
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
    <div className="flex flex-col gap-[14px]">
      <div className="text-[0.62rem] tracking-[0.14em] uppercase text-muted pb-[10px] border-b border-border">
        {title}
      </div>
      <div className="flex flex-col">{children}</div>
    </div>
  );
}

function FindingCard({ severity, children }) {
  return (
    <div
      className="px-4 py-3 border-l-[3px] bg-[#fafaf8] rounded-[0_5px_5px_0] mb-2"
      style={{ borderLeftColor: SEVERITY_COLOR[severity] }}
    >
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
