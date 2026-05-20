import { useState } from "react";
import styles from "../styles/HeroSection.module.css";

export default function HeroSection({ onScan, loading, error }) {
  const [repoUrl, setRepoUrl] = useState("");

  const handleSubmit = () => { if (repoUrl.trim()) onScan(repoUrl.trim()); };
  const handleKey = (e) => { if (e.key === "Enter") handleSubmit(); };

  return (
    <section className={styles.section}>
      <div className={styles.inner}>

        <div className={styles.eyebrow}>
          <span className={styles.eyebrowDot} />
          Threat Intelligence Platform
        </div>

        <h1 className={styles.title}>
          <span className={styles.titleLine1}>Scan your {"<"}Codebase{"/>"}</span>
          <em className={styles.titleLine2}>Find the blast radius.</em>
        </h1>

        <p className={styles.sub}>
          AI-powered security analysis for LLM-assisted codebases.
          Uncover attack paths before someone else does.
        </p>

        <div className={styles.inputBlock}>
          <label className={styles.label}>Repository URL</label>
          <input
            className={styles.input}
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            onKeyDown={handleKey}
            placeholder="https://github.com/owner/repo"
            disabled={loading}
          />
          <button
            className={`${styles.btn} ${loading ? styles.btnDisabled : ""}`}
            onClick={handleSubmit}
            disabled={loading}
          >
            {loading ? "◌  Scanning…" : "▸  Run Scan"}
          </button>
          {error && <p className={styles.error}>{error}</p>}
        </div>

      </div>
    </section>
  );
}
