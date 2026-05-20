export const styles = {
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

export const blockStyles = {
  root: { display: "flex", flexDirection: "column", gap: "14px" },
  title: {
    fontSize: "0.62rem", letterSpacing: "0.14em", textTransform: "uppercase",
    color: "#6b6860", paddingBottom: "10px", borderBottom: "1px solid #d4cfc6",
  },
  body: { display: "flex", flexDirection: "column" },
};

export const findingStyles = {
  card: {
    padding: "12px 16px", borderLeft: "3px solid",
    backgroundColor: "#fafaf8", borderRadius: "0 5px 5px 0", marginBottom: "8px",
  },
};