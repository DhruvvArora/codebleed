import styles from "../styles/UpcomingSection.module.css";

const UPCOMING = [
  {
    icon: "◎",
    title: "Private repository support",
    desc: "Scan private repos by providing your own GitHub token. Your credentials never leave your session.",
    status: "In progress",
  },
  {
    icon: "◈",
    title: "GitHub Actions integration",
    desc: "Run Omen as part of your CI/CD pipeline. Block merges when new attack paths are introduced.",
    status: "Planned",
  },
  {
    icon: "◆",
    title: "SARIF export",
    desc: "Export findings in the standard Static Analysis Results Interchange Format for integration with GitHub Security and other tools.",
    status: "Planned",
  },
  {
    icon: "▸",
    title: "Team dashboards",
    desc: "Share scan history across your team. Track risk score over time as fixes are applied.",
    status: "Planned",
  },
];

export default function UpcomingSection() {
  return (
    <section className={styles.section}>
      <div className={styles.inner}>

        <div className={styles.header}>
          <p className={styles.eyebrow}>
            <span className={styles.eyebrowDot} /> What's coming
          </p>
          <h2 className={styles.title}>Still building.</h2>
          <p className={styles.sub}>
            Omen is early. These features are on the roadmap — drop a note if any of them matter to you.
          </p>
        </div>

        <div className={styles.list}>
          {UPCOMING.map(({ icon, title, desc, status }) => (
            <div key={title} className={styles.item}>
              <span className={styles.itemIcon}>{icon}</span>
              <div className={styles.itemContent}>
                <div className={styles.itemTop}>
                  <h3 className={styles.itemTitle}>{title}</h3>
                  <span className={`${styles.badge} ${status === "In progress" ? styles.badgeActive : ""}`}>
                    {status}
                  </span>
                </div>
                <p className={styles.itemDesc}>{desc}</p>
              </div>
            </div>
          ))}
        </div>

      </div>
    </section>
  );
}
