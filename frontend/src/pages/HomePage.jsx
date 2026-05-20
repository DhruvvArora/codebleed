import { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import HeroSection from "../components/HeroSection";
import FeaturesSection from "../components/FeaturesSection";
import UpcomingSection from "../components/UpcomingSection";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

export default function HomePage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const handleScan = async (repoUrl) => {
    setLoading(true);
    setError(null);

    try {
      const { data } = await axios.post(`${API_BASE}/scan`, {
        repo_url: repoUrl,
        branch: "main",
        scan_mode: "full",
        include_commit_history: true,
        include_dependencies: true,
        include_secrets: true,
        include_endpoints: true,
      });

      // Pass scan data to results page via router state
      navigate("/results", { state: { scanData: data, repoUrl } });
    } catch (err) {
      setError(err?.response?.data?.detail || "Scan failed. Check the repo URL and try again.");
      setLoading(false);
    }
  };

  return (
    <main>
      <HeroSection onScan={handleScan} loading={loading} error={error} />
      <FeaturesSection />
      <UpcomingSection />
    </main>
  );
}
