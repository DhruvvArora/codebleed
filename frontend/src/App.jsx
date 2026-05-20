import { BrowserRouter, Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import HomePage from "./pages/HomePage";
import ResultsPage from "./pages/ResultsPage";
import "./styles/global.css";

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-root">
        <div className="noise" />
        <Navbar />
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/results" element={<ResultsPage />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}
