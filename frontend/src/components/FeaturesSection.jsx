import styles from "../styles/FeaturesSection.module.css";

const FEATURES = [
  {
    icon: "◈",
    title: "Attack path analysis",
    desc: "Visualize how vulnerabilities chain together. Omen traces paths from public entry points through risky files and dependencies to sensitive assets.",
    points: ["Endpoint → secret chains", "Commit-level attribution", "Blast radius scoring"],
  },
  {
    icon: "◎",
    title: "CVE matching",
    desc: "Cross-reference every dependency in your repo against known vulnerability databases. Catch risky packages before they become incidents.",
    points: ["requirements.txt + package.json", "Heuristic risk detection", "Affected file mapping"],
  },
  {
    icon: "◆",
    title: "Secret detection",
    desc: "Regex-based scanner that catches hardcoded API keys, tokens, and credentials across your full commit history — not just the latest snapshot.",
    points: ["40+ secret patterns", "Commit-level attribution", "Author identification"],
  },
  {
    icon: "▸",
    title: "AI reasoning",
    desc: "GPT-4o synthesizes the graph output into a structured analyst report — executive summary, key findings, and prioritized fixes, ready to act on.",
    points: ["Executive + dev summaries", "Fix simulation", "Confidence scoring"],
  },
];

export default function FeaturesSection() {
  return (
    <section className={styles.section}>
      <div className={styles.inner}>

        <div className={styles.header}>
          <p className={styles.eyebrow}>
            <span className={styles.eyebrowDot} /> What Omen detects
          </p>
          <h2 className={styles.title}>
            Graph-powered security,<br />
            <em className={styles.titleItalic}>end to end.</em>
          </h2>
          <p className={styles.sub}>
            Built specifically for AI-assisted and vibe-coded repositories,
            where context collapses fast and attack surfaces grow faster.
          </p>
        </div>

        <div className={styles.grid}>
          {FEATURES.map(({ icon, title, desc, points }) => (
            <div key={title} className={styles.card}>
              <span className={styles.cardIcon}>{icon}</span>
              <h3 className={styles.cardTitle}>{title}</h3>
              <p className={styles.cardDesc}>{desc}</p>
              <ul className={styles.cardPoints}>
                {points.map((p) => (
                  <li key={p} className={styles.cardPoint}>
                    <span className={styles.pointDot}>·</span> {p}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

      </div>
    </section>
  );
}
