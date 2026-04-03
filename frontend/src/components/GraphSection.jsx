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
            highlight: {
              background: colors.bg,
              border: SEVERITY_COLOR[n.severity] || colors.bg,
            },
            hover: {
              background: colors.bg,
              border: SEVERITY_COLOR[n.severity] || colors.bg,
            },
          },
          font: {
            color: colors.fg,
            size: isHighlighted ? 15 : 13,
            face: "DM Mono, monospace",
          },
          borderWidth: isHighlighted ? 4 : 2,
          shadow: false,
          // ? {
          //   enabled: true,
          //   color: SEVERITY_COLOR[n.severity] || colors.bg,
          //   size: 18,
          //   x: 0,
          //   y: 0,
          // }
          // : {
          //   enabled: true,
          //   color: "rgba(0,0,0,0.25)",
          //   size: 8,
          //   x: 0,
          //   y: 2,
          // },
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
          // label: e.type,
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
      nodes: {
        borderWidth: 2,
        margin: 10,
        scaling: { min: 20, max: 40 },
      },
      edges: {
        length: 220,
        smooth: false,
      },
      layout: {
        improvedLayout: true,
      },
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
        stabilization: {
          enabled: true,
          iterations: 80,
          updateInterval: 25,
          fit: true,
        },
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

    if (networkRef.current) {
      networkRef.current.destroy();
    }

    setNetworkReady(false);

    networkRef.current = new window.vis.Network(
      containerRef.current,
      { nodes, edges },
      options
    );

    networkRef.current.once("stabilized", () => {
      networkRef.current.fit({
        animation: {
          duration: 200,
          easingFunction: "easeInOutQuad",
        },
      });
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
    <div style={styles.root}>
      <div style={styles.topBar}>
        <div style={styles.topLeft}>
          <span style={styles.sectionLabel}>◈ Threat Graph</span>
          {scanData && (
            <span style={styles.graphMeta}>
              {scanData.graph.nodes.length} nodes · {scanData.graph.edges.length} edges
            </span>
          )}
          {networkReady && <span style={styles.readyBadge}>stabilized</span>}
        </div>

        {selectedPath && (
          <div style={styles.pathBadge}>
            <span
              style={{
                ...styles.pathSev,
                color: SEVERITY_COLOR[selectedPath.severity] || "#2d7a4f",
              }}
            >
              {selectedPath.severity.toUpperCase()}
            </span>
            <span style={styles.pathLabel}>
              {selectedPath.path_type.replace(/_/g, " ")} · score {selectedPath.risk_score}
            </span>
          </div>
        )}

        {scanData && (
          <button style={styles.reportBtn} onClick={onViewReport}>
            AI Report ↓
          </button>
        )}
      </div>

      <div style={styles.canvasWrap}>
        {!scanData ? (
          <div style={styles.empty}>
            <span style={styles.emptyIcon}>◈</span>
            <p style={styles.emptyTitle}>Threat graph</p>
            <p style={styles.emptyText}>
              Run a scan to visualize your repository as a threat graph
            </p>
          </div>
        ) : (
          <>
            <div ref={containerRef} style={styles.canvas} />

            <div style={styles.zoomControls}>
              <button
                type="button"
                style={styles.zoomBtn}
                onClick={() =>
                  networkRef.current?.moveTo({
                    scale: (networkRef.current.getScale() || 1) * 1.2,
                  })
                }
              >
                +
              </button>
              <button
                type="button"
                style={styles.zoomBtn}
                onClick={() =>
                  networkRef.current?.moveTo({
                    scale: (networkRef.current.getScale() || 1) / 1.2,
                  })
                }
              >
                −
              </button>
            </div>

            <div style={styles.legend}>
              {Object.entries(LABEL_COLOR).map(([label, colors]) => (
                <div key={label} style={styles.legendItem}>
                  <span style={{ ...styles.legendDot, backgroundColor: colors.bg }} />
                  <span style={styles.legendLabel}>{label}</span>
                </div>
              ))}
            </div>

            {hoveredNode && (
              <div style={styles.tooltip}>
                <div style={styles.tooltipLabel}>{hoveredNode.label}</div>
                <div style={styles.tooltipName}>{hoveredNode.name}</div>
                <div style={styles.tooltipRow}>
                  <span
                    style={{
                      color: SEVERITY_COLOR[hoveredNode.severity] || "#2d7a4f",
                    }}
                  >
                    {hoveredNode.severity}
                  </span>
                  <span style={styles.tooltipScore}>
                    risk {hoveredNode.risk_score ?? 0}
                  </span>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {selectedPath && scanData && (
        <div style={styles.chainBar}>
          <span style={styles.chainLabel}>Attack Chain</span>
          <div style={styles.chain}>
            {selectedPath.node_ids.map((nodeId, i) => {
              const node = scanData.graph.nodes.find((n) => n.id === nodeId);

              return (
                <span key={nodeId} style={styles.chainStep}>
                  <span
                    style={{
                      ...styles.chainNode,
                      borderColor: node
                        ? SEVERITY_COLOR[node.severity] || "#6b6860"
                        : "#6b6860",
                    }}
                  >
                    {node?.name || nodeId}
                  </span>
                  {i < selectedPath.node_ids.length - 1 && (
                    <span style={styles.chainArrow}>→</span>
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

const styles = {
  root: {
    display: "flex",
    flexDirection: "column",
    minHeight: "calc(100vh - 53px)",
    color: "#f5f2eb",
  },
  topBar: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "24px 56px",
    borderBottom: "1px solid #252522",
    flexWrap: "wrap",
    gap: "12px",
  },
  topLeft: {
    display: "flex",
    alignItems: "center",
    gap: "20px",
    flexWrap: "wrap",
  },
  sectionLabel: {
    fontFamily: "'Fraunces', serif",
    fontSize: "1.1rem",
    color: "#2d7a4f",
    letterSpacing: "-0.01em",
  },
  graphMeta: {
    fontSize: "0.65rem",
    color: "#4a4a48",
    letterSpacing: "0.08em",
  },
  readyBadge: {
    fontSize: "0.62rem",
    color: "#2d7a4f",
    border: "1px solid #2d7a4f",
    borderRadius: "999px",
    padding: "4px 10px",
    letterSpacing: "0.08em",
    textTransform: "uppercase",
  },
  pathBadge: {
    display: "flex",
    alignItems: "center",
    gap: "12px",
    padding: "8px 16px",
    border: "1px solid #2a2a28",
    borderRadius: "5px",
  },
  pathSev: {
    fontSize: "0.62rem",
    letterSpacing: "0.1em",
    fontWeight: 700,
  },
  pathLabel: {
    fontSize: "0.68rem",
    color: "#6b6860",
  },
  reportBtn: {
    padding: "9px 20px",
    fontFamily: "'DM Mono', monospace",
    fontSize: "0.75rem",
    backgroundColor: "transparent",
    color: "#2d7a4f",
    border: "1px solid #2d7a4f",
    borderRadius: "5px",
    cursor: "pointer",
    letterSpacing: "0.04em",
  },
  canvasWrap: {
    flex: 1,
    position: "relative",
    height: "calc(100vh - 150px)",
    minHeight: "760px",
    overflow: "hidden",
  },
  canvas: {
    width: "100%",
    height: "100%",
    position: "absolute",
    inset: 0,
    background: "radial-gradient(circle at center, #171715 0%, #111110 65%, #0c0c0b 100%)",
  },
  zoomControls: {
    position: "absolute",
    top: "24px",
    right: "24px",
    display: "flex",
    flexDirection: "column",
    gap: "10px",
    zIndex: 5,
  },
  zoomBtn: {
    width: "42px",
    height: "42px",
    borderRadius: "6px",
    border: "1px solid #2d7a4f",
    backgroundColor: "#111110",
    color: "#2d7a4f",
    fontSize: "1.3rem",
    cursor: "pointer",
    fontFamily: "'DM Mono', monospace",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  empty: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    height: "100%",
    minHeight: "500px",
    gap: "16px",
  },
  emptyIcon: {
    fontSize: "3rem",
    color: "#2d7a4f",
    opacity: 0.4,
  },
  emptyTitle: {
    fontFamily: "'Fraunces', serif",
    fontSize: "1.6rem",
    color: "#f5f2eb",
    opacity: 0.3,
    margin: 0,
    letterSpacing: "-0.02em",
  },
  emptyText: {
    fontSize: "0.78rem",
    color: "#6b6860",
    margin: 0,
  },
  legend: {
    position: "absolute",
    bottom: "24px",
    left: "24px",
    display: "flex",
    flexWrap: "wrap",
    gap: "10px",
    maxWidth: "520px",
    zIndex: 4,
  },
  legendItem: {
    display: "flex",
    alignItems: "center",
    gap: "6px",
  },
  legendDot: {
    width: "8px",
    height: "8px",
    borderRadius: "50%",
    flexShrink: 0,
  },
  legendLabel: {
    fontSize: "0.6rem",
    color: "#8a857d",
    letterSpacing: "0.06em",
  },
  tooltip: {
    position: "absolute",
    top: "24px",
    right: "86px",
    backgroundColor: "#111110",
    border: "1px solid #2d7a4f",
    borderRadius: "6px",
    padding: "14px 18px",
    display: "flex",
    flexDirection: "column",
    gap: "4px",
    minWidth: "170px",
    zIndex: 4,
  },
  tooltipLabel: {
    fontSize: "0.6rem",
    letterSpacing: "0.12em",
    textTransform: "uppercase",
    color: "#2d7a4f",
  },
  tooltipName: {
    fontSize: "0.88rem",
    color: "#f5f2eb",
    fontWeight: 500,
  },
  tooltipRow: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    fontSize: "0.7rem",
    marginTop: "4px",
  },
  tooltipScore: {
    color: "#6b6860",
  },
  chainBar: {
    padding: "18px 56px",
    borderTop: "1px solid #252522",
    display: "flex",
    alignItems: "flex-start",
    gap: "24px",
    flexWrap: "wrap",
  },
  chainLabel: {
    fontSize: "0.62rem",
    letterSpacing: "0.12em",
    textTransform: "uppercase",
    color: "#2d7a4f",
    flexShrink: 0,
    paddingTop: "3px",
  },
  chain: {
    display: "flex",
    alignItems: "center",
    flexWrap: "wrap",
    gap: "6px",
  },
  chainStep: {
    display: "flex",
    alignItems: "center",
    gap: "6px",
  },
  chainNode: {
    fontSize: "0.7rem",
    padding: "4px 12px",
    border: "1px solid",
    borderRadius: "3px",
    color: "#f5f2eb",
    backgroundColor: "#1a1a18",
  },
  chainArrow: {
    fontSize: "0.75rem",
    color: "#2d7a4f",
  },
};