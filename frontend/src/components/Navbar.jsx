import { Link } from "react-router-dom";
import styles from "../styles/Navbar.module.css";

export default function Navbar() {
  return (
    <header className={styles.header}>
      <div className={styles.inner}>
        <Link to="/" className={styles.logo}>
          <span className={styles.logoDot}>▸</span> Omen
        </Link>
        <span className={styles.badge}>Threat Intelligence</span>
      </div>
    </header>
  );
}
