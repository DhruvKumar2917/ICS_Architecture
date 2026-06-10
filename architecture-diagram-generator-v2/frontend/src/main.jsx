import React, { useCallback, useState, useEffect, memo } from "react";
import { createRoot } from "react-dom/client";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Panel,
  addEdge,
  useNodesState,
  useEdgesState,
  MarkerType,
  Handle,
  Position,
  ReactFlowProvider,
  useViewport,
  useReactFlow
} from "reactflow";
import "reactflow/dist/style.css";
import axios from "axios";
import dagre from "dagre";
import {
  Upload,
  FileText,
  Network,
  AlertTriangle,
  Shield,
  ShieldAlert,
  Cpu,
  Terminal,
  Zap,
  Compass,
  RefreshCw,
  Target
} from "lucide-react";
import "./style.css";

const API_URL = "http://127.0.0.1:8000";

// Color maps for node categories
const typeColors = {
  firewall: "#ffe4e6",
  server: "#dbeafe",
  database: "#dcfce7",
  vpn: "#ede9fe",
  cloud: "#fef9c3",
  plc: "#ffedd5",
  scada: "#e0f2fe",
  network: "#f3f4f6",
  zone: "#f5f5f4",
  component: "#ffffff",
  user: "#fae8ff"
};

// Custom Node component for ICS Assets
const ICSNode = memo(({ data }) => {
  const criticality = data.criticality || "medium";
  const purdueLevel = data.purdue_level || "unknown";
  const type = data.type || "component";
  const inAttackPath = data.in_attack_path;
  const isEnforcement = data.is_enforcement_point;
  const isExposedBlast = data.is_exposed_blast;
  const isCompromisedSource = data.is_compromised_source;

  let critBorderColor = "#94a3b8";
  if (criticality === "critical") critBorderColor = "#ef4444";
  else if (criticality === "high") critBorderColor = "#f97316";
  else if (criticality === "medium") critBorderColor = "#eab308";

  const customStyle = {
    borderColor: isCompromisedSource 
      ? "#a855f7" 
      : inAttackPath 
      ? "#ef4444" 
      : isExposedBlast 
      ? "#f97316" 
      : critBorderColor,
    boxShadow: isCompromisedSource
      ? "0 0 20px rgba(168, 85, 247, 0.8)"
      : inAttackPath 
      ? "0 0 20px rgba(239, 68, 68, 0.8)" 
      : isExposedBlast 
      ? "0 0 20px rgba(249, 115, 22, 0.7)" 
      : "none",
    borderWidth: inAttackPath || isExposedBlast || isCompromisedSource ? "3px" : "1.5px"
  };

  return (
    <div className={`ics-node ${inAttackPath ? "pulse-red" : ""}`} style={customStyle}>
      <Handle type="target" position={Position.Top} className="node-handle" />
      
      <div className="ics-node-header">
        <span className="ics-node-type">{type.toUpperCase()}</span>
        {purdueLevel !== "unknown" && (
          <span className="ics-node-purdue">{purdueLevel}</span>
        )}
      </div>

      <div className="ics-node-body">
        <div className="ics-node-name">{data.label || "Asset"}</div>
      </div>

      <div className="ics-node-footer">
        {criticality === "critical" && (
          <span className="badge badge-critical">CRITICAL</span>
        )}
        {isEnforcement && (
          <span className="badge badge-enforcement">SECURE</span>
        )}
        {isCompromisedSource && (
          <span className="badge badge-compromised">COMPROMISED</span>
        )}
        {isExposedBlast && !isCompromisedSource && (
          <span className="badge badge-exposed">EXPOSED</span>
        )}
      </div>

      <button 
        className="blast-btn" 
        onClick={(e) => {
          e.stopPropagation();
          if (data.onBlastRadius) data.onBlastRadius(data.id);
        }}
        title="Analyze compromise impact"
      >
        <Zap size={10} style={{ marginRight: 2 }} /> Impact
      </button>

      <Handle type="source" position={Position.Bottom} className="node-handle" />
    </div>
  );
});

const nodeTypes = {
  icsNode: ICSNode
};

// Custom interactive scrollbar component for ReactFlow viewport
const CustomScrollbars = () => {
  const { x, y, zoom } = useViewport();
  const { setViewport, getNodes } = useReactFlow();
  const [containerSize, setContainerSize] = useState({ width: 800, height: 600 });
  const [isDraggingH, setIsDraggingH] = useState(false);
  const [isDraggingV, setIsDraggingV] = useState(false);

  useEffect(() => {
    const handleResize = () => {
      const rfEl = document.querySelector(".react-flow");
      if (rfEl) {
        setContainerSize({
          width: rfEl.clientWidth,
          height: rfEl.clientHeight
        });
      }
    };
    const timer = setTimeout(handleResize, 200);
    window.addEventListener("resize", handleResize);
    return () => {
      clearTimeout(timer);
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  const nodes = getNodes();
  if (nodes.length === 0) return null;

  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;

  nodes.forEach((node) => {
    if (!node.parentNode) {
      const nx = node.position.x;
      const ny = node.position.y;
      let w = 180;
      let h = 80;
      if (node.style) {
        if (typeof node.style.width === 'number') w = node.style.width;
        else if (typeof node.style.width === 'string') w = parseInt(node.style.width, 10) || 180;

        if (typeof node.style.height === 'number') h = node.style.height;
        else if (typeof node.style.height === 'string') h = parseInt(node.style.height, 10) || 80;
      }
      if (nx < minX) minX = nx;
      if (nx + w > maxX) maxX = nx + w;
      if (ny < minY) minY = ny;
      if (ny + h > maxY) maxY = ny + h;
    }
  });

  if (minX === Infinity) return null;

  const margin = 100;
  const W_total = (maxX - minX) + 2 * margin;
  const H_total = (maxY - minY) + 2 * margin;
  const total_minX = minX - margin;
  const total_minY = minY - margin;

  const W_visible = containerSize.width / zoom;
  const H_visible = containerSize.height / zoom;

  const showH = W_total > W_visible;
  const showV = H_total > H_visible;

  if (!showH && !showV) return null;

  const trackMargin = 20;
  const scrollbarThickness = 8;
  const S_width = containerSize.width - 2 * trackMargin - (showV ? 20 : 0);
  const thumbWidth = Math.max(40, S_width * Math.min(1, W_visible / W_total));
  const X_scroll = (-x / zoom) - total_minX;
  const scrollFractionX = Math.max(0, Math.min(1, X_scroll / (W_total - W_visible)));
  const thumbLeft = (S_width - thumbWidth) * scrollFractionX;

  const S_height = containerSize.height - 2 * trackMargin - (showH ? 20 : 0);
  const thumbHeight = Math.max(40, S_height * Math.min(1, H_visible / H_total));
  const Y_scroll = (-y / zoom) - total_minY;
  const scrollFractionY = Math.max(0, Math.min(1, Y_scroll / (H_total - H_visible)));
  const thumbTop = (S_height - thumbHeight) * scrollFractionY;

  const handleMouseDownH = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDraggingH(true);
    const startClientX = e.clientX;
    const startThumbLeft = thumbLeft;

    const handleMouseMove = (moveEvent) => {
      const deltaX = moveEvent.clientX - startClientX;
      let newThumbLeft = startThumbLeft + deltaX;
      newThumbLeft = Math.max(0, Math.min(S_width - thumbWidth, newThumbLeft));
      const newFractionX = newThumbLeft / (S_width - thumbWidth);
      const newXScroll = newFractionX * (W_total - W_visible);
      const newX = -(newXScroll + total_minX) * zoom;
      setViewport({ x: newX, y, zoom });
    };

    const handleMouseUp = () => {
      setIsDraggingH(false);
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
    };

    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseup", handleMouseUp);
  };

  const handleMouseDownV = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDraggingV(true);
    const startClientY = e.clientY;
    const startThumbTop = thumbTop;

    const handleMouseMove = (moveEvent) => {
      const deltaY = moveEvent.clientY - startClientY;
      let newThumbTop = startThumbTop + deltaY;
      newThumbTop = Math.max(0, Math.min(S_height - thumbHeight, newThumbTop));
      const newFractionY = newThumbTop / (S_height - thumbHeight);
      const newYScroll = newFractionY * (H_total - H_visible);
      const newY = -(newYScroll + total_minY) * zoom;
      setViewport({ x, y: newY, zoom });
    };

    const handleMouseUp = () => {
      setIsDraggingV(false);
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
    };

    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseup", handleMouseUp);
  };

  const handleTrackClickH = (e) => {
    if (e.target.className === "scrollbar-thumb") return;
    const rect = e.currentTarget.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    let newThumbLeft = clickX - thumbWidth / 2;
    newThumbLeft = Math.max(0, Math.min(S_width - thumbWidth, newThumbLeft));
    const newFractionX = newThumbLeft / (S_width - thumbWidth);
    const newXScroll = newFractionX * (W_total - W_visible);
    const newX = -(newXScroll + total_minX) * zoom;
    setViewport({ x: newX, y, zoom });
  };

  const handleTrackClickV = (e) => {
    if (e.target.className === "scrollbar-thumb") return;
    const rect = e.currentTarget.getBoundingClientRect();
    const clickY = e.clientY - rect.top;
    let newThumbTop = clickY - thumbHeight / 2;
    newThumbTop = Math.max(0, Math.min(S_height - thumbHeight, newThumbTop));
    const newFractionY = newThumbTop / (S_height - thumbHeight);
    const newYScroll = newFractionY * (H_total - H_visible);
    const newY = -(newYScroll + total_minY) * zoom;
    setViewport({ x, y: newY, zoom });
  };

  return (
    <>
      {showH && (
        <Panel position="bottom-left" style={{ left: `${trackMargin}px`, bottom: "8px", margin: 0, pointerEvents: "none" }}>
          <div
            className={`custom-scrollbar horizontal ${isDraggingH ? "active" : ""}`}
            style={{
              width: `${S_width}px`,
              height: `${scrollbarThickness}px`,
              background: "rgba(30, 41, 59, 0.5)",
              borderRadius: "4px",
              cursor: "pointer",
              pointerEvents: "all",
              position: "relative"
            }}
            onClick={handleTrackClickH}
          >
            <div
              className="scrollbar-thumb"
              style={{
                position: "absolute",
                left: `${thumbLeft}px`,
                top: 0,
                width: `${thumbWidth}px`,
                height: "100%",
                background: "rgba(148, 163, 184, 0.7)",
                borderRadius: "4px",
                cursor: "grab",
                transition: "background 0.15s ease"
              }}
              onMouseDown={handleMouseDownH}
            />
          </div>
        </Panel>
      )}
      {showV && (
        <Panel position="top-right" style={{ right: "8px", top: `${trackMargin}px`, margin: 0, pointerEvents: "none" }}>
          <div
            className={`custom-scrollbar vertical ${isDraggingV ? "active" : ""}`}
            style={{
              height: `${S_height}px`,
              width: `${scrollbarThickness}px`,
              background: "rgba(30, 41, 59, 0.5)",
              borderRadius: "4px",
              cursor: "pointer",
              pointerEvents: "all",
              position: "relative"
            }}
            onClick={handleTrackClickV}
          >
            <div
              className="scrollbar-thumb"
              style={{
                position: "absolute",
                top: `${thumbTop}px`,
                left: 0,
                height: `${thumbHeight}px`,
                width: "100%",
                background: "rgba(148, 163, 184, 0.7)",
                borderRadius: "4px",
                cursor: "grab",
                transition: "background 0.15s ease"
              }}
              onMouseDown={handleMouseDownV}
            />
          </div>
        </Panel>
      )}
    </>
  );
};

function layoutGraph(nodes, edges) {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "LR", nodesep: 80, ranksep: 120 });

  nodes.forEach((node) => {
    g.setNode(node.id, { width: 180, height: 75 });
  });

  edges.forEach((edge) => {
    g.setEdge(edge.source, edge.target);
  });

  dagre.layout(g);

  return nodes.map((node) => {
    const pos = g.node(node.id) || { x: 0, y: 0 };
    return {
      ...node,
      position: {
        x: pos.x - 90,
        y: pos.y - 37
      }
    };
  });
}

function App() {
  const [text, setText] = useState(
    "vendor_operator connects to vendor_vpn. vendor_vpn connects to Master SCADA Server. Master SCADA Server connects to Turbine HMI. Turbine HMI connects to PLC_Unit_1. PLC_Unit_1 connects to Valve_Actuator_A."
  );
  const [file, setFile] = useState(null);
  const [selectedRole, setSelectedRole] = useState("vendor_operator");
  const [message, setMessage] = useState("Upload architecture input files to begin analysis.");
  const [loading, setLoading] = useState(false);

  // Core analysis results state
  const [analysis, setAnalysis] = useState(null);
  const [viewMode, setViewMode] = useState("asset"); // "asset" or "zone"
  const [activeTab, setActiveTab] = useState("inputs"); // "inputs", "audit", "paths", "reachability"
  const [activePathIndex, setActivePathIndex] = useState(-1);
  const [blastNode, setBlastNode] = useState(null);
  const [blastReport, setBlastReport] = useState(null);

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  const onConnect = useCallback(
    (params) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  );

  // Computes the visual nodes/edges to display depending on settings
  const applyViewPayload = useCallback(() => {
    if (!analysis) return;

    if (viewMode === "zone") {
      // Zone macro view
      const rawNodes = analysis.react_flow_macro_zone_view.nodes.map((n) => ({
        ...n,
        style: {
          background: "#1e293b",
          border: "2px solid #3b82f6",
          color: "#f8fafc",
          borderRadius: 12,
          padding: 16,
          fontSize: 14,
          fontWeight: 600,
          textAlign: "center",
          width: 180
        }
      }));
      const rawEdges = analysis.react_flow_macro_zone_view.edges.map((e) => ({
        ...e,
        animated: true,
        markerEnd: { type: MarkerType.ArrowClosed, color: "#3b82f6" },
        style: { stroke: "#3b82f6", strokeWidth: 2 }
      }));

      const laidOut = layoutGraph(rawNodes, rawEdges);
      setNodes(laidOut);
      setEdges(rawEdges);
      return;
    }

    // Detailed asset view (Purdue grouped layout)
    const baseNodes = JSON.parse(JSON.stringify(analysis.react_flow_asset_view.nodes));
    const baseEdges = JSON.parse(JSON.stringify(analysis.react_flow_asset_view.edges));

    let pathNodeIds = new Set();
    let pathEdgePairs = new Set();

    // Check if we have an active threat path highlighted
    if (activePathIndex >= 0 && analysis.attack_paths && analysis.attack_paths[activePathIndex]) {
      const activePath = analysis.attack_paths[activePathIndex].path;
      pathNodeIds = new Set(activePath);
      for (let i = 0; i < activePath.length - 1; i++) {
        pathEdgePairs.add(`${activePath[i]}->${activePath[i+1]}`);
      }
    }

    // Check if we have active blast radius highlighted
    const blastExposedIds = new Set(blastReport?.exposed_entities?.critical_assets || []);
    (blastReport?.exposed_entities?.physical_processes || []).forEach(p => blastExposedIds.add(p));

    // Map properties to React Flow nodes
    const renderedNodes = baseNodes.map(n => {
      if (n.type === "icsNode") {
        return {
          ...n,
          data: {
            ...n.data,
            onBlastRadius: handleAnalyzeBlastRadius,
            in_attack_path: pathNodeIds.has(n.id),
            is_exposed_blast: blastExposedIds.has(n.id) || (blastReport && n.id === blastNode),
            is_compromised_source: blastNode && n.id === blastNode
          }
        };
      }
      // Group container rendering
      return {
        ...n,
        style: {
          ...n.style,
          background: "rgba(15, 23, 42, 0.03)",
          border: "2px dashed #94a3b8",
          borderRadius: 16,
          color: "#475569",
          fontWeight: 700,
          fontSize: 12,
          padding: 8
        }
      };
    });

    // Map properties to React Flow edges
    const renderedEdges = baseEdges.map(e => {
      const edgeKey = `${e.source}->${e.target}`;
      const inPath = pathEdgePairs.has(edgeKey);
      
      if (inPath) {
        return {
          ...e,
          animated: true,
          style: { stroke: "#ef4444", strokeWidth: 4.5 },
          markerEnd: { type: MarkerType.ArrowClosed, color: "#ef4444" }
        };
      } else if (activePathIndex >= 0) {
        // Fade out other edges
        return {
          ...e,
          style: { stroke: "#cbd5e1", strokeWidth: 1.5, opacity: 0.3 }
        };
      }
      
      // Standard layout
      return {
        ...e,
        animated: e.animated || false,
        style: { stroke: "#475569", strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#475569" }
      };
    });

    setNodes(renderedNodes);
    setEdges(renderedEdges);

  }, [analysis, viewMode, activePathIndex, blastNode, blastReport]);

  useEffect(() => {
    applyViewPayload();
  }, [applyViewPayload]);

  const handleAnalyzeBlastRadius = async (nodeId) => {
    if (!analysis || !analysis.raw_model_data) return;
    try {
      setMessage(`Running blast radius analysis for compromised node: ${nodeId}...`);
      const res = await axios.post(`${API_URL}/blast-radius`, {
        graph_data: analysis.raw_model_data,
        node_id: nodeId
      });
      if (res.data.error) {
        setMessage(`Blast analysis error: ${res.data.error}`);
      } else {
        setBlastNode(nodeId);
        setBlastReport(res.data);
        setActivePathIndex(-1); // Turn off attack paths
        setActiveTab("reachability");
        setMessage(`Blast radius calculation complete for: ${nodeId}`);
      }
    } catch (err) {
      console.error(err);
      setMessage(`Blast radius analysis failed: ${err.message}`);
    }
  };

  const clearBlastHighlight = () => {
    setBlastNode(null);
    setBlastReport(null);
  };

  const handleResponseData = (data) => {
    setAnalysis(data);
    setActivePathIndex(-1);
    clearBlastHighlight();

    if (data.validation_report && !data.validation_report.is_valid) {
      setActiveTab("audit");
      setMessage("Analysis complete. Architectural errors detected in security validation!");
    } else if (data.attack_paths && data.attack_paths.length > 0) {
      setActiveTab("paths");
      setMessage(`Analysis complete. Found ${data.attack_paths.length} potential risk paths!`);
    } else {
      setActiveTab("audit");
      setMessage("Analysis complete. Architecture is structurally sound!");
    }
  };

  const generateFromText = async () => {
    try {
      setLoading(true);
      setMessage("Building security model from text...");
      const res = await axios.post(
        `${API_URL}/generate-from-text`,
        { text, role: selectedRole },
        { headers: { "Content-Type": "application/json" } }
      );
      if (res.data.error) {
        setMessage(res.data.error);
      } else {
        handleResponseData(res.data);
      }
    } catch (err) {
      console.error(err);
      setMessage(err.message || "Backend connection error");
    } finally {
      setLoading(false);
    }
  };

  const generateFromFile = async () => {
    if (!file) {
      setMessage("Please select a file first.");
      return;
    }
    try {
      setLoading(true);
      setMessage(`Uploading and auditing file: ${file.name}...`);
      const formData = new FormData();
      formData.append("file", file);

      const res = await axios.post(
        `${API_URL}/upload?role=${encodeURIComponent(selectedRole)}`,
        formData
      );
      
      if (res.data.error) {
        setMessage(res.data.error);
      } else {
        handleResponseData(res.data);
      }
    } catch (err) {
      console.error(err);
      setMessage(err.message || "File analysis failed");
    } finally {
      setLoading(false);
    }
  };

  const downloadJson = () => {
    if (!analysis) return;
    const blob = new Blob([JSON.stringify(analysis, null, 2)], {
      type: "application/json"
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "ics-security-model.json";
    a.click();
  };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <Shield size={28} className="shield-icon" />
          <div>
            <h1>ICS Audit & Security Graph</h1>
            <p>Phase 2: ISA-62443 Threat Modeler & Parser</p>
          </div>
        </div>

        {/* Tab Selector buttons */}
        <div className="tab-menu">
          <button 
            className={`tab-btn ${activeTab === "inputs" ? "active" : ""}`}
            onClick={() => setActiveTab("inputs")}
          >
            Inputs
          </button>
          <button 
            className={`tab-btn ${activeTab === "audit" ? "active" : ""}`}
            onClick={() => setActiveTab("audit")}
            disabled={!analysis}
          >
            Audit Report
          </button>
          <button 
            className={`tab-btn ${activeTab === "paths" ? "active" : ""}`}
            onClick={() => setActiveTab("paths")}
            disabled={!analysis}
          >
            Attack Paths
          </button>
          <button 
            className={`tab-btn ${activeTab === "reachability" ? "active" : ""}`}
            onClick={() => setActiveTab("reachability")}
            disabled={!analysis}
          >
            Blast Radius
          </button>
        </div>

        {/* Tab 1: Inputs & Uploads */}
        {activeTab === "inputs" && (
          <div className="tab-content">
            <section className="card">
              <h2>
                <Target size={18} /> Entry-Role Configuration
              </h2>
              <p className="hint">Specify which operator/entry-point role starts the attack path queries:</p>
              <input
                type="text"
                placeholder="e.g. vendor_operator, admin"
                value={selectedRole}
                onChange={(e) => setSelectedRole(e.target.value)}
                className="role-input"
              />
            </section>

            <section className="card">
              <h2>
                <FileText size={18} /> Textual Description
              </h2>
              <textarea 
                value={text} 
                onChange={(e) => setText(e.target.value)} 
                placeholder="Type architecture description..."
              />
              <button onClick={generateFromText} disabled={loading}>
                {loading ? <RefreshCw className="animate-spin" size={16} /> : "Compile Text Model"}
              </button>
            </section>

            <section className="card">
              <h2>
                <Upload size={18} /> File Upload
              </h2>
              <input
                type="file"
                accept=".png,.jpg,.jpeg,.webp,.pdf,.csv,.xlsx,.txt"
                onChange={(e) => setFile(e.target.files[0])}
              />
              <button onClick={generateFromFile} disabled={loading}>
                {loading ? <RefreshCw className="animate-spin" size={16} /> : "Upload & Analyze Architecture"}
              </button>
              <p className="hint">Supports Architecture Images, PDFs, CSV, and Excel tables.</p>
            </section>
          </div>
        )}

        {/* Tab 2: Security Validation Audits */}
        {activeTab === "audit" && analysis && (
          <div className="tab-content animate-fade">
            <section className="card score-card">
              <h2>Architecture Health Index</h2>
              <div className="gauge-box">
                <span className={`gauge-score ${analysis.validation_report.is_valid ? "green" : "red"}`}>
                  {analysis.validation_report.is_valid ? "100%" : "FAIL"}
                </span>
                <span className="gauge-label">Structural DAG Verification</span>
              </div>
            </section>

            <section className="card audit-card">
              <h2>
                <AlertTriangle size={18} style={{ color: "#ef4444" }} /> Validation Errors ({analysis.validation_report.errors.length})
              </h2>
              {analysis.validation_report.errors.length === 0 ? (
                <p className="audit-ok">No structural errors. Graph is a valid DAG.</p>
              ) : (
                <ul className="audit-list error-list">
                  {analysis.validation_report.errors.map((err, i) => (
                    <li key={i}>{err}</li>
                  ))}
                </ul>
              )}
            </section>

            <section className="card audit-card">
              <h2>
                <ShieldAlert size={18} style={{ color: "#f97316" }} /> Security Warnings ({analysis.validation_report.warnings.length})
              </h2>
              {analysis.validation_report.warnings.length === 0 ? (
                <p className="audit-ok">No security warnings found.</p>
              ) : (
                <ul className="audit-list warning-list">
                  {analysis.validation_report.warnings.map((warn, i) => (
                    <li key={i}>{warn}</li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        )}

        {/* Tab 3: Quantitative Threat Path Inspector */}
        {activeTab === "paths" && analysis && (
          <div className="tab-content animate-fade">
            <section className="card">
              <h2>Top Critical Attack Vectors</h2>
              <p className="hint">Discovered paths from '{selectedRole || "Entry Points"}' to critical final targets:</p>
              
              {analysis.attack_paths.length === 0 ? (
                <p className="audit-ok">No threat vectors found bridging entry roles to targets.</p>
              ) : (
                <div className="paths-list">
                  {analysis.attack_paths.map((path, idx) => (
                    <div 
                      key={idx}
                      className={`path-item ${activePathIndex === idx ? "selected" : ""}`}
                      onClick={() => {
                        clearBlastHighlight();
                        setActivePathIndex(activePathIndex === idx ? -1 : idx);
                      }}
                    >
                      <div className="path-meta">
                        <span className="path-idx">Vector #{idx + 1}</span>
                        <span className="path-risk">Risk: {path.overall_risk}</span>
                      </div>
                      <div className="path-details">
                        <span>Impact: {path.impact_score}</span>
                        <span>Likelihood: {Math.round(path.likelihood_score * 100)}%</span>
                      </div>
                      <div className="path-narrative-short">
                        {path.path.join(" ➔ ")}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            {activePathIndex >= 0 && analysis.attack_paths[activePathIndex] && (
              <section className="card narrative-card animate-fade">
                <h2>Analyst Attack Narrative</h2>
                <div className="narrative-text">
                  {analysis.attack_paths[activePathIndex].narrative.split("\n\n").map((para, i) => (
                    <p key={i}>{para}</p>
                  ))}
                  {analysis.attack_paths[activePathIndex].realism_warnings.length > 0 && (
                    <div className="realism-box">
                      <strong>Architecture Warnings:</strong>
                      <ul>
                        {analysis.attack_paths[activePathIndex].realism_warnings.map((w, i) => (
                          <li key={i}>{w}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </section>
            )}
          </div>
        )}

        {/* Tab 4: Cyber-Physical Reachability & Blast Radius */}
        {activeTab === "reachability" && analysis && (
          <div className="tab-content animate-fade">
            <section className="card">
              <h2>Compromise Blast Radius</h2>
              <p className="hint">Exposes downstream cyber/physical processes if an asset is compromised.</p>
              
              {!blastNode ? (
                <div className="blast-empty">
                  <Terminal size={32} />
                  <p>Click the <strong>Impact</strong> button on any asset node in the diagram to compute its structural compromise blast radius.</p>
                </div>
              ) : (
                <div className="blast-report">
                  <div className="blast-header">
                    <h3>Compromised: <span>{blastNode}</span></h3>
                    <button className="clear-btn" onClick={clearBlastHighlight}>Clear</button>
                  </div>
                  
                  {blastReport && (
                    <div className="blast-stats">
                      <div className="blast-stat">
                        <span className="num">{blastReport.operational_summary.total_assets_exposed}</span>
                        <span className="lbl">Total Assets Exposed</span>
                      </div>
                      <div className="blast-stat">
                        <span className="num">{blastReport.operational_summary.critical_assets_exposed}</span>
                        <span className="lbl">Critical Cyber Exposed</span>
                      </div>
                      <div className="blast-stat">
                        <span className="num">{blastReport.operational_summary.physical_processes_exposed}</span>
                        <span className="lbl">Physical Processes Lost</span>
                      </div>
                    </div>
                  )}

                  {blastReport && blastReport.exposed_entities.critical_assets.length > 0 && (
                    <div className="blast-details">
                      <h4>Exposed Critical Cyber:</h4>
                      <ul>
                        {blastReport.exposed_entities.critical_assets.map((a, i) => (
                          <li key={i}>{a}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {blastReport && blastReport.exposed_entities.physical_processes.length > 0 && (
                    <div className="blast-details">
                      <h4>Compromised Physics:</h4>
                      <ul>
                        {blastReport.exposed_entities.physical_processes.map((p, i) => (
                          <li key={i}>{p}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </section>

            <section className="card">
              <h2>Cyber-to-Physical Exposure Vectors</h2>
              <p className="hint">Direct multi-hop connections starting from entry points terminating at Level 0 actuators:</p>
              {analysis.reachability_data.cyber_physical_vectors.length === 0 ? (
                <p className="audit-ok">No direct cyber-physical exposure paths found.</p>
              ) : (
                <ul className="vector-list">
                  {analysis.reachability_data.cyber_physical_vectors.map((vec, i) => (
                    <li key={i}>
                      <div className="vec-title">{vec.source} ➔ {vec.target}</div>
                      <div className="vec-meta">
                        <span>Confidence: {vec.confidence}</span>
                        <span>Length: {vec.path_length} hops</span>
                      </div>
                      <div className="vec-summary">{vec.explanation.summary}</div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        )}

        <section className="card system-status">
          <h2>System Logs</h2>
          <p className="message-box">{message}</p>
          {analysis && <button onClick={downloadJson}>Download Audited JSON</button>}
        </section>
      </aside>

      <main className="canvas">
        {analysis && (
          <div className="canvas-header">
            <div className="view-selector">
              <button 
                className={viewMode === "asset" ? "active" : ""} 
                onClick={() => setViewMode("asset")}
              >
                <Cpu size={16} /> Asset Purdue View
              </button>
              <button 
                className={viewMode === "zone" ? "active" : ""} 
                onClick={() => setViewMode("zone")}
              >
                <Compass size={16} /> Macro Zone View
              </button>
            </div>
            <div className="view-legend">
              <span className="legend-hint" style={{ marginRight: 12, borderRight: "1px solid #334155", paddingRight: 12, color: "#94a3b8" }}>
                💡 Scroll to Pan | Ctrl + Scroll to Zoom
              </span>
              <span className="legend-item"><span className="dot red"></span> Critical</span>
              <span className="legend-item"><span className="dot orange"></span> High</span>
              <span className="legend-item"><span className="dot blue"></span> Secure Enforcement</span>
            </div>
          </div>
        )}

        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ minZoom: 0.2, maxZoom: 1.2 }}
          minZoom={0.1}
          maxZoom={2}
          panOnScroll={true}
          panOnScrollMode="free"
          zoomOnScroll={false}
        >
          <Background color="#cbd5e1" gap={16} />
          <Controls />
          <MiniMap nodeColor={(n) => typeColors[n.type] || "#ffffff"} />
          <CustomScrollbars />
        </ReactFlow>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(
  <ReactFlowProvider>
    <App />
  </ReactFlowProvider>
);