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
  const [repoUrl, setRepoUrl] = useState("https://github.com/DhruvvArora/codebleed");

  const handleSubmit = () => { if (repoUrl.trim()) onScan(repoUrl.trim()); };
  const handleKey = (e) => { if (e.key === "Enter") handleSubmit(); };

  return (
    <div className="flex flex-col min-h-[calc(100vh-53px)]">

      {/* Hero Section */}
      <div className="min-h-[calc(100vh-53px)] flex items-center justify-center px-8 py-20 box-border">
        <div className="flex flex-col items-center text-center gap-9 w-full max-w-[1320px] mx-auto">

          <div className="flex items-center gap-[10px] text-[1.1rem] tracking-[0.14em] uppercase text-accent">
            <span className="w-2 h-2 rounded-full bg-accent inline-block shrink-0" />
            Threat Intelligence Platform
          </div>

          <h1 className="font-display text-[clamp(3rem,5vw,5.2rem)] font-normal leading-[1.02] tracking-[-0.03em] text-dark m-0">
            Scan your repo.<br />
            <em className="italic text-accent whitespace-nowrap inline-block">Find the blast radius.</em>
          </h1>

          <p className="text-[clamp(1.05rem,1.6vw,1.3rem)] text-muted leading-[1.7] max-w-[540px] m-0">
            Graph-powered security analysis for AI-assisted codebases.
            Uncover attack paths before someone else does.
          </p>

          {/* Input block */}
          <div className="flex flex-col gap-3 w-full max-w-[700px]">
            <label className="text-base tracking-[0.12em] uppercase text-muted text-left">
              GitHub Repository URL
            </label>
            <input
              className="w-full px-5 py-4 font-mono text-[0.95rem] bg-white border border-border rounded-[5px] text-dark outline-none box-border"
              type="text"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              onKeyDown={handleKey}
              placeholder="https://github.com/owner/repo"
              disabled={loading}
            />
            <button
              className={`py-[18px] font-mono text-[1.05rem] bg-dark text-light border-none rounded-[5px] cursor-pointer tracking-[0.06em] w-full${loading ? " opacity-50 cursor-not-allowed" : ""}`}
              onClick={handleSubmit}
              disabled={loading}
            >
              {loading ? "◌  Scanning…" : "▸  Run Scan"}
            </button>
            {error && <p className="text-[0.82rem] text-critical m-0 text-left">{error}</p>}
          </div>

          {/* Feature list */}
          <div className="grid grid-cols-4 w-full max-w-[1400px] mx-auto px-2 box-border text-left border-t border-border pt-8">
            {[
              ["◈", "Attack path graph", "Model your repo as a Neo4j threat graph"],
              ["◎", "CVE matching", "Cross-reference deps against OSV.dev"],
              ["◆", "Secret detection", "Regex-based secrets scanner across commits"],
              ["▸", "AI reasoning", "RocketRide AI generates prioritized fix reports"],
            ].map(([icon, title, desc], i, arr) => (
              <div
                key={title}
                className={`flex gap-[14px] items-start px-7 min-w-0${i < arr.length - 1 ? " border-r border-border" : ""}`}
              >
                <span className="text-[1.2rem] text-accent mt-[3px] shrink-0">{icon}</span>
                <div>
                  <div className="text-[1.08rem] text-dark font-medium mb-[6px]">{title}</div>
                  <div className="text-[0.95rem] text-muted leading-[1.55]">{desc}</div>
                </div>
              </div>
            ))}
          </div>

        </div>
      </div>

      {/* Bottom panel */}
      <div className="border-t border-border w-full">
        {!scanData && !loading && (
          <div className="flex flex-col items-center justify-center px-[60px] py-20 text-center gap-5">
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
            <p className="font-display text-[1.8rem] text-dark tracking-[-0.02em] m-0">
              Attack paths will appear here
            </p>
            <p className="text-[0.85rem] text-muted leading-[1.7] max-w-[400px] m-0">
              After scanning, CodeBleed maps your repo as a threat graph and surfaces
              the most dangerous paths from entry points to sensitive assets.
            </p>
          </div>
        )}

        {loading && (
          <div className="flex flex-col items-center justify-center px-[60px] py-20 text-center gap-5">
            <div className="w-14 h-14 rounded-full border-2 border-accent opacity-50" style={{ animation: "spin 2s linear infinite" }} />
            <p className="font-display text-[1.8rem] text-dark tracking-[-0.02em] m-0">Building threat graph…</p>
            <p className="text-[0.85rem] text-muted leading-[1.7] max-w-[400px] m-0">
              Fetching commits · Matching CVEs · Running AI analysis
            </p>
          </div>
        )}

        {scanData && (
          <div className="px-16 py-12 flex flex-col gap-5 max-w-[960px] mx-auto w-full box-border">
            <div className="flex items-center justify-between pb-[14px] border-b border-border">
              <span className="text-[0.7rem] tracking-[0.14em] uppercase text-dark font-semibold">Attack Paths</span>
              <span className="text-[0.7rem] text-muted">{scanData.attack_paths.length} detected</span>
            </div>
            <div className="flex flex-col gap-[10px]">
              {scanData.attack_paths.map((path) => (
                <PathCard
                  key={path.path_id}
                  path={path}
                  selected={path.path_id === selectedPathId}
                  onSelect={() => onPathSelect(path.path_id)}
                />
              ))}
            </div>
            <div className="border-t border-[#f0ece4]" />
            <div className="flex items-center justify-between pb-[14px] border-b border-border">
              <span className="text-[0.7rem] tracking-[0.14em] uppercase text-dark font-semibold">Top Risks</span>
            </div>
            <div className="flex flex-col">
              {scanData.top_risks.map((risk) => (
                <div key={risk.id} className="flex items-center justify-between py-[14px] border-b border-[#f0ece4]">
                  <div className="flex items-center gap-[10px] flex-1">
                    <span
                      className="w-2 h-2 rounded-full shrink-0"
                      style={{ backgroundColor: SEVERITY_COLOR[risk.severity] }}
                    />
                    <span className="text-[0.85rem] text-dark leading-[1.4]">{risk.title}</span>
                  </div>
                  <span
                    className="font-display text-[1.5rem] ml-5 shrink-0"
                    style={{ color: SEVERITY_COLOR[risk.severity] }}
                  >
                    {risk.risk_score}
                  </span>
                </div>
              ))}
            </div>
            <button
              className="self-start mt-2 px-7 py-[13px] font-mono text-[0.85rem] bg-dark text-light border-none rounded-[5px] cursor-pointer tracking-[0.06em]"
              onClick={onViewReport}
            >
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
    <div
      className={`px-[22px] py-5 border rounded-[6px] cursor-pointer bg-white flex flex-col gap-2 transition-[border-color,box-shadow] duration-150${selected ? " border-accent shadow-[0_0_0_3px_rgba(45,122,79,0.1)]" : " border-border"}`}
      onClick={onSelect}
    >
      <div className="flex justify-between items-center">
        <span
          className="text-[0.65rem] tracking-[0.1em] font-bold"
          style={{ color: SEVERITY_COLOR[path.severity] }}
        >
          {path.severity.toUpperCase()}
        </span>
        <span className="text-[0.72rem] text-muted">{path.risk_score} / 100</span>
      </div>
      <p className="text-[0.85rem] text-dark m-0 leading-[1.55]">{path.summary}</p>
      <div className="text-[0.65rem] text-muted">
        {path.node_ids.length} nodes · {path.edge_ids.length} edges · {path.path_type.replace(/_/g, " ")}
      </div>
    </div>
  );
}
