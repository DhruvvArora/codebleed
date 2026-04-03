import { useEffect, useRef, useState } from "react";

const LABEL_COLOR = {
  Repository: { bg: "#2d7a4f", fg: "#fff" },
  Developer: { bg: "#3182ce", fg: "#fff" },
  Commit: { bg: "#6b6860", fg: "#fff" },
  File: { bg: "#d69e2e", fg: "#1a1a18" },
  Dependency: { bg: "#805ad5", fg: "#fff" },
  Vulnerability: { bg: "#e53e3e", fg: "#fff" },
  Secret: { bg: "#c53030", fg: "#fff" },
  Endpoint: { bg: "#dd6b20", fg: "#fff" },
  RiskFinding: { bg: "#9b2335", fg: "#fff" },
};

const SEVERITY_COLOR = {
  critical: "#e53e3e",
  high: "#dd6b20",
  medium: "#d69e2e",
  low: "#2d7a4f",
};

export default function GraphSection({ scanData, selectedPathId, onViewReport }) {
  const containerRef = useRef(null);
  const networkRef = useRef(null);
  const [visLoaded, setVisLoaded] = useState(false);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [networkReady, setNetworkReady] = useState(false);

  useEffect(() => {
    if (window.vis) {
      setVisLoaded(true);
      return;
    }

    const script = document.createElement("script");
    script.src = "https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js";
    script.onload = () => setVisLoaded(true);
    document.head.appendChild(script);

    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css";
    document.head.appendChild(link);
  }, []);

  useEffect(() => {
    if (!visLoaded || !scanData?.graph || !containerRef.current) return;

    const rawNodes = scanData.graph.nodes || [];
    const rawEdges = scanData.graph.edges || [];
    const attackPaths = scanData.attack_paths || [];
    const selectedPath = attackPaths.find((p) => p.path_id === selectedPathId);

    const highlightedNodes = new Set(selectedPath?.node_ids || []);
    const highlightedEdges = new Set(selectedPath?.edge_ids || []);

    const nodes = new window.vis.DataSet(
      rawNodes.map((n) => {
        const colors = LABEL_COLOR[n.label] || { bg: "#6b6860", fg: "#fff" };
        const isHighlighted = highlightedNodes.has(n.id);

        return {
          id: n.id,
          label: `${n.name}\n[${n.label}]`,
          color: {
            background: colors.bg,
            border: isHighlighted ? (SEVERITY_COLOR[n.severity] || colors.bg) : colors.bg,
            highlight: { background: colors.bg, border: SEVERITY_COLOR[n.severity] || colors.bg },
            hover: { background: colors.bg, border: SEVERITY_COLOR[n.severity] || colors.bg },
          },
          font: {
            color: colors.fg,
            size: isHighlighted ? 15 : 13,
            face: "DM Mono, monospace",
          },
          borderWidth: isHighlighted ? 4 : 2,
          shadow: false,
          size: isHighlighted ? 34 : 24,
          shape: shapeForLabel(n.label),
          title: buildTooltip(n),
        };
      })
    );

    const edges = new window.vis.DataSet(
      rawEdges.map((e) => {
        const isHighlighted = highlightedEdges.has(e.id);

        return {
          id: e.id,
          from: e.source ?? e.from,
          to: e.target ?? e.to,
          label: "",
          color: {
            color: isHighlighted ? "#2d7a4f" : "#6b6860",
            highlight: "#2d7a4f",
            hover: "#2d7a4f",
          },
          width: isHighlighted ? 3 : 1.6,
          font: {
            color: isHighlighted ? "#2d7a4f" : "#8a857d",
            size: 10,
            face: "DM Mono, monospace",
            strokeWidth: 0,
          },
          arrows: { to: { enabled: true, scaleFactor: 0.75 } },
          smooth: false,
          dashes: !isHighlighted,
        };
      })
    );

    const options = {
      autoResize: true,
      nodes: { borderWidth: 2, margin: 10, scaling: { min: 20, max: 40 } },
      edges: { length: 220, smooth: false },
      layout: { improvedLayout: true },
      physics: {
        enabled: true,
        solver: "forceAtlas2Based",
        forceAtlas2Based: {
          gravitationalConstant: -120,
          centralGravity: 0.01,
          springLength: 220,
          springConstant: 0.03,
          damping: 0.7,
          avoidOverlap: 1,
        },
        stabilization: { enabled: true, iterations: 80, updateInterval: 25, fit: true },
      },
      interaction: {
        hover: true,
        tooltipDelay: 120,
        dragView: true,
        zoomView: false,
        navigationButtons: false,
        keyboard: false,
      },
    };

    if (networkRef.current) networkRef.current.destroy();
    setNetworkReady(false);

    networkRef.current = new window.vis.Network(containerRef.current, { nodes, edges }, options);

    networkRef.current.once("stabilized", () => {
      networkRef.current.fit({ animation: { duration: 200, easingFunction: "easeInOutQuad" } });
      networkRef.current.setOptions({ physics: false });
      setNetworkReady(true);
    });

    networkRef.current.on("hoverNode", (params) => {
      const node = rawNodes.find((n) => n.id === params.node);
      if (node) setHoveredNode(node);
    });

    networkRef.current.on("blurNode", () => setHoveredNode(null));

    return () => {
      networkRef.current?.destroy();
      networkRef.current = null;
    };
  }, [visLoaded, scanData]);

  const selectedPath = scanData?.attack_paths?.find((p) => p.path_id === selectedPathId);

  return (
    <div className="flex flex-col min-h-[calc(100vh-53px)] text-light">

      {/* Top bar */}
      <div className="flex items-center justify-between px-14 py-6 border-b border-[#252522] flex-wrap gap-3">
        <div className="flex items-center gap-5 flex-wrap">
          <span className="font-display text-[1.1rem] text-accent tracking-[-0.01em]">◈ Threat Graph</span>
          {scanData && (
            <span className="text-[0.65rem] text-[#4a4a48] tracking-[0.08em]">
              {scanData.graph.nodes.length} nodes · {scanData.graph.edges.length} edges
            </span>
          )}
          {networkReady && (
            <span className="text-[0.62rem] text-accent border border-accent rounded-full px-[10px] py-1 tracking-[0.08em] uppercase">
              stabilized
            </span>
          )}
        </div>

        {selectedPath && (
          <div className="flex items-center gap-3 px-4 py-2 border border-[#2a2a28] rounded-[5px]">
            <span
              className="text-[0.62rem] tracking-[0.1em] font-bold"
              style={{ color: SEVERITY_COLOR[selectedPath.severity] || "#2d7a4f" }}
            >
              {selectedPath.severity.toUpperCase()}
            </span>
            <span className="text-[0.68rem] text-muted">
              {selectedPath.path_type.replace(/_/g, " ")} · score {selectedPath.risk_score}
            </span>
          </div>
        )}

        {scanData && (
          <button
            className="px-5 py-[9px] font-mono text-[0.75rem] bg-transparent text-accent border border-accent rounded-[5px] cursor-pointer tracking-[0.04em]"
            onClick={onViewReport}
          >
            AI Report ↓
          </button>
        )}
      </div>

      {/* Canvas area */}
      <div className="flex-1 relative overflow-hidden" style={{ height: "calc(100vh - 150px)", minHeight: "760px" }}>
        {!scanData ? (
          <div className="flex flex-col items-center justify-center h-full min-h-[500px] gap-4">
            <span className="text-[3rem] text-accent opacity-40">◈</span>
            <p className="font-display text-[1.6rem] text-light opacity-30 m-0 tracking-[-0.02em]">Threat graph</p>
            <p className="text-[0.78rem] text-muted m-0">
              Run a scan to visualize your repository as a threat graph
            </p>
          </div>
        ) : (
          <>
            <div
              ref={containerRef}
              className="w-full h-full absolute inset-0"
              style={{ background: "radial-gradient(circle at center, #171715 0%, #111110 65%, #0c0c0b 100%)" }}
            />

            {/* Zoom controls */}
            <div className="absolute top-6 right-6 flex flex-col gap-[10px] z-[5]">
              <button
                type="button"
                className="w-[42px] h-[42px] rounded-[6px] border border-accent bg-[#111110] text-accent text-[1.3rem] cursor-pointer font-mono flex items-center justify-center"
                onClick={() => networkRef.current?.moveTo({ scale: (networkRef.current.getScale() || 1) * 1.2 })}
              >
                +
              </button>
              <button
                type="button"
                className="w-[42px] h-[42px] rounded-[6px] border border-accent bg-[#111110] text-accent text-[1.3rem] cursor-pointer font-mono flex items-center justify-center"
                onClick={() => networkRef.current?.moveTo({ scale: (networkRef.current.getScale() || 1) / 1.2 })}
              >
                −
              </button>
            </div>

            {/* Legend */}
            <div className="absolute bottom-6 left-6 flex flex-wrap gap-[10px] max-w-[520px] z-[4]">
              {Object.entries(LABEL_COLOR).map(([label, colors]) => (
                <div key={label} className="flex items-center gap-[6px]">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: colors.bg }} />
                  <span className="text-[0.6rem] text-[#8a857d] tracking-[0.06em]">{label}</span>
                </div>
              ))}
            </div>

            {/* Hover tooltip */}
            {hoveredNode && (
              <div className="absolute top-6 right-[86px] bg-[#111110] border border-accent rounded-[6px] px-[18px] py-[14px] flex flex-col gap-1 min-w-[170px] z-[4]">
                <div className="text-[0.6rem] tracking-[0.12em] uppercase text-accent">{hoveredNode.label}</div>
                <div className="text-[0.88rem] text-light font-medium">{hoveredNode.name}</div>
                <div className="flex items-center justify-between text-[0.7rem] mt-1">
                  <span style={{ color: SEVERITY_COLOR[hoveredNode.severity] || "#2d7a4f" }}>
                    {hoveredNode.severity}
                  </span>
                  <span className="text-muted">risk {hoveredNode.risk_score ?? 0}</span>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Attack chain bar */}
      {selectedPath && scanData && (
        <div className="px-14 py-[18px] border-t border-[#252522] flex items-start gap-6 flex-wrap">
          <span className="text-[0.62rem] tracking-[0.12em] uppercase text-accent shrink-0 pt-[3px]">
            Attack Chain
          </span>
          <div className="flex items-center flex-wrap gap-[6px]">
            {selectedPath.node_ids.map((nodeId, i) => {
              const node = scanData.graph.nodes.find((n) => n.id === nodeId);
              return (
                <span key={nodeId} className="flex items-center gap-[6px]">
                  <span
                    className="text-[0.7rem] px-3 py-1 border rounded-[3px] text-light bg-dark"
                    style={{ borderColor: node ? SEVERITY_COLOR[node.severity] || "#6b6860" : "#6b6860" }}
                  >
                    {node?.name || nodeId}
                  </span>
                  {i < selectedPath.node_ids.length - 1 && (
                    <span className="text-[0.75rem] text-accent">→</span>
                  )}
                </span>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function shapeForLabel(label) {
  return (
    {
      Repository: "diamond",
      Developer: "circle",
      Commit: "dot",
      File: "square",
      Dependency: "triangle",
      Vulnerability: "triangleDown",
      Secret: "star",
      Endpoint: "ellipse",
      RiskFinding: "hexagon",
    }[label] || "dot"
  );
}

function buildTooltip(n) {
  return `<div style="font-family:monospace;font-size:11px;padding:10px 12px;background:#1a1a18;color:#f5f2eb;border-radius:5px;border:1px solid #2d7a4f;line-height:1.6">
    <strong style="color:#2d7a4f">${n.label}</strong><br/>${n.name}<br/>
    severity: ${n.severity ?? "unknown"} · risk: ${n.risk_score ?? 0}
  </div>`;
}
