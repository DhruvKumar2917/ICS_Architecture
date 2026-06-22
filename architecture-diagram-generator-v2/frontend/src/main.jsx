import React, { useCallback, useState, useEffect, memo } from "react";
import { createRoot } from "react-dom/client";
import ReactFlow, {
  Background, BackgroundVariant, Controls, MiniMap,
  addEdge, useNodesState, useEdgesState,
  MarkerType, Handle, Position, ReactFlowProvider,
} from "reactflow";
import "reactflow/dist/style.css";
import axios from "axios";
import dagre from "dagre";
import {
  Shield, Upload, FileText, AlertTriangle, ShieldAlert,
  Cpu, Compass, RefreshCw, Zap, Terminal, Lock,
  Network, UserCheck, GitBranch, Activity, Eye,
  CheckCircle, XCircle, ChevronRight, Database,
} from "lucide-react";
import "./style.css";

const API_URL = "http://127.0.0.1:8000";

// ---------------------------------------------------------------------------
// Type → minimap colour
// ---------------------------------------------------------------------------
const typeColors = {
  firewall: "#ffe4e6", server: "#dbeafe", database: "#dcfce7",
  vpn: "#ede9fe", plc: "#ffedd5", scada: "#e0f2fe",
  zone: "#f5f5f4", user: "#fae8ff", subject: "#f3e8ff",
  object: "#ecfeff", component: "#ffffff",
};

// ---------------------------------------------------------------------------
// Custom ICS Node
// ---------------------------------------------------------------------------
const ICSNode = memo(({ data }) => {
  const criticality      = data.criticality || "medium";
  const purdueLevel      = data.purdue_level || "";
  const type             = data.type || "component";
  const inAttackPath     = data.in_attack_path;
  const isEnforcement    = data.is_enforcement_point;
  const isExposedBlast   = data.is_exposed_blast;
  const isCompromised    = data.is_compromised_source;

  let borderColor = "#334155";
  if (isCompromised)    borderColor = "#a855f7";
  else if (inAttackPath) borderColor = "#ef4444";
  else if (isExposedBlast) borderColor = "#f97316";
  else if (criticality === "critical") borderColor = "#ef4444";
  else if (criticality === "high")     borderColor = "#f97316";
  else if (criticality === "medium")   borderColor = "#eab308";

  const glow = isCompromised
    ? "0 0 22px rgba(168,85,247,0.8)"
    : inAttackPath
    ? "0 0 22px rgba(239,68,68,0.8)"
    : isExposedBlast
    ? "0 0 20px rgba(249,115,22,0.7)"
    : "none";

  return (
    <div
      className={`ics-node ${inAttackPath ? "pulse-red" : ""}`}
      style={{ borderColor, boxShadow: glow, borderWidth: (inAttackPath || isExposedBlast || isCompromised) ? "2px" : "1.5px" }}
    >
      <Handle type="target" position={Position.Top} className="node-handle" />

      <div className="ics-node-header">
        <span className="ics-node-type">{type.toUpperCase()}</span>
        {purdueLevel && purdueLevel !== "unknown" && (
          <span className="ics-node-purdue">{purdueLevel}</span>
        )}
      </div>

      <div className="ics-node-name">{data.label || "Asset"}</div>

      <div className="ics-node-footer">
        {criticality === "critical" && <span className="badge badge-critical">CRITICAL</span>}
        {isEnforcement    && <span className="badge badge-enforce">SECURE</span>}
        {isCompromised    && <span className="badge badge-subject">COMPROMISED</span>}
        {isExposedBlast && !isCompromised && <span className="badge badge-exposed">EXPOSED</span>}
        <button
          className="blast-btn"
          onClick={(e) => { e.stopPropagation(); data.onBlastRadius?.(data.id); }}
          title="Analyze compromise impact"
        >
          <Zap size={8} /> Impact
        </button>
      </div>

      <Handle type="source" position={Position.Bottom} className="node-handle" />
    </div>
  );
});

const ICSZoneGroup = memo(({ data, id }) => (
  <div className="ics-zone-group">
    <div className="ics-zone-header">
      {data.label || id.replace("group_", "").replace(/_/g, " ").toUpperCase()}
    </div>
  </div>
));

const nodeTypes = { icsNode: ICSNode, icsGroup: ICSZoneGroup };

// ---------------------------------------------------------------------------
// Dagre layout
// ---------------------------------------------------------------------------
function layoutGraph(nodes, edges) {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "LR", nodesep: 100, ranksep: 160, marginx: 40, marginy: 40 });
  nodes.forEach((n) => g.setNode(n.id, { width: 190, height: 90 }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map((n) => {
    const p = g.node(n.id) || { x: 0, y: 0 };
    return { ...n, position: { x: p.x - 95, y: p.y - 45 } };
  });
}

// ---------------------------------------------------------------------------
// Helper components
// ---------------------------------------------------------------------------
function EmptyState({ icon: Icon, message }) {
  return (
    <div className="empty-state">
      <Icon size={28} />
      <p>{message}</p>
    </div>
  );
}

function SectionSep({ label }) {
  return <div className="section-sep">{label}</div>;
}

// ---------------------------------------------------------------------------
// RBAC Tab
// ---------------------------------------------------------------------------
function RBACTab({ rbacSummary, permissions }) {
  const subjects    = rbacSummary?.S || [];
  const actions     = rbacSummary?.R || [];
  const perms       = rbacSummary?.permissions || permissions || [];
  const hasData = subjects.length > 0;

  if (!hasData) {
    return (
      <EmptyState
        icon={UserCheck}
        message="No RBAC file was uploaded. Upload a JSON/CSV/TXT policy file to see subjects, actions, and permissions extracted from the authoritative RBAC source."
      />
    );
  }

  return (
    <>
      <div className="card animate-in">
        <div className="card-title"><UserCheck size={14} /> Subjects (S) — Authorization Principals</div>
        <p className="hint">Extracted exclusively from the uploaded RBAC file. Never inferred from the diagram.</p>
        <ul className="aasg-list">
          {subjects.map((s, i) => (
            <li key={i} className="rbac-subject-item">
              <Lock size={11} />
              <span>{s.name || s.id}</span>
              <span style={{ marginLeft: "auto", opacity: 0.6, fontSize: "9px" }}>{s.kind}</span>
            </li>
          ))}
        </ul>
      </div>

      {actions.length > 0 && (
        <div className="card animate-in">
          <div className="card-title"><Activity size={14} /> Actions (R) — Permitted Operations</div>
          <div className="actions-wrap">
            {actions.map((a, i) => (
              <span key={i} className="rbac-action-item">{a.name || a.id}</span>
            ))}
          </div>
        </div>
      )}

      {perms.length > 0 && (
        <div className="card animate-in">
          <div className="card-title"><GitBranch size={14} /> Permissions (E_a sources)</div>
          <div style={{ overflowX: "auto", maxHeight: 240, overflowY: "auto" }}>
            <table className="perm-table">
              <thead>
                <tr>
                  <th>Subject</th>
                  <th>Action</th>
                  <th>Object</th>
                  <th>Role</th>
                </tr>
              </thead>
              <tbody>
                {perms.slice(0, 50).map((p, i) => (
                  <tr key={i}>
                    <td className="perm-sub">{p.subject}</td>
                    <td className="perm-act">{p.action}</td>
                    <td className="perm-obj">{p.object}</td>
                    <td style={{ color: "#64748b", fontSize: "9px" }}>{p.role_provenance || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Firewall Tab
// ---------------------------------------------------------------------------
function FirewallTab({ firewallSummary, firewallBlocked }) {
  const rules   = firewallSummary?.rules || [];
  const blocked = firewallBlocked || [];

  if (rules.length === 0 && blocked.length === 0) {
    return (
      <EmptyState
        icon={Network}
        message="No firewall file was uploaded. Upload a JSON/CSV/TXT firewall rules file to constrain communication edges (Ec) in the AASG."
      />
    );
  }

  const allowed = rules.filter((r) => ["allow", "accept", "permit", "pass"].includes(r.action));
  const denied  = rules.filter((r) => !["allow", "accept", "permit", "pass"].includes(r.action));

  return (
    <>
      <div className="card animate-in">
        <div className="card-title"><CheckCircle size={14} style={{ color: "var(--success)" }} /> Allowed Connections ({allowed.length})</div>
        <ul className="aasg-list">
          {allowed.map((r, i) => (
            <li key={i} className="fw-rule-item allowed">
              <span className="fw-src">{r.src_raw || r.src}</span>
              <span className="fw-arrow">→</span>
              <span className="fw-dst">{r.dst_raw || r.dst}</span>
              <span className="badge badge-allowed">{r.protocol}{r.port ? `:${r.port}` : ""}</span>
            </li>
          ))}
        </ul>
      </div>

      {denied.length > 0 && (
        <div className="card animate-in">
          <div className="card-title"><XCircle size={14} style={{ color: "var(--danger)" }} /> Denied Rules ({denied.length})</div>
          <ul className="aasg-list">
            {denied.map((r, i) => (
              <li key={i} className="fw-rule-item denied">
                <span className="fw-src">{r.src_raw || r.src}</span>
                <span className="fw-arrow">⊘</span>
                <span className="fw-dst">{r.dst_raw || r.dst}</span>
                <span className="badge badge-blocked">{r.protocol}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {blocked.length > 0 && (
        <div className="card animate-in">
          <div className="card-title"><ShieldAlert size={14} style={{ color: "var(--warning)" }} /> Blocked by Firewall ({blocked.length})</div>
          <p className="hint">Architecture links removed from Ec because no firewall allow-rule was found.</p>
          <ul className="aasg-list">
            {blocked.map((b, i) => (
              <li key={i} className="fw-blocked-item">
                <XCircle size={10} />
                <span>{b.src} → {b.dst}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// AASG Model Tab
// ---------------------------------------------------------------------------
function AASGTab({ aasg }) {
  if (!aasg) return <EmptyState icon={GitBranch} message="Run analysis to see the formal AASG." />;

  const subjects  = (aasg.V || []).filter((v) => v.vertex_type === "subject");
  const objects   = (aasg.V || []).filter((v) => v.vertex_type === "object");
  const ea        = aasg.E?.E_a || [];
  const ec        = aasg.E?.E_c || [];
  const stats     = aasg.stats || {};

  return (
    <>
      {/* Math definition */}
      <div className="math-banner animate-in">
        <span className="math-expr">G = (V, E, Z)</span>
        <span className="math-expr">V = S ∪ O</span>
        <span className="math-expr">E = E<sub>a</sub> ∪ E<sub>c</sub></span>
      </div>

      {/* Stats row */}
      <div className="stat-grid animate-in">
        <div className="stat-cell"><span className="stat-val" style={{ color: "var(--subject-color)" }}>{stats.subject_count ?? subjects.length}</span><span className="stat-label">Subjects</span></div>
        <div className="stat-cell"><span className="stat-val" style={{ color: "var(--object-color)" }}>{stats.object_count ?? objects.length}</span><span className="stat-label">Objects</span></div>
        <div className="stat-cell"><span className="stat-val" style={{ color: "var(--ea-color)" }}>{stats.ea_count ?? ea.length}</span><span className="stat-label">Auth Edges</span></div>
        <div className="stat-cell"><span className="stat-val" style={{ color: "var(--ec-color)" }}>{stats.ec_count ?? ec.length}</span><span className="stat-label">Comm Edges</span></div>
      </div>

      {/* Zones */}
      <div className="card animate-in">
        <div className="aasg-section-title"><span className="zone-dot" />Zones (Z) — Security Boundaries</div>
        <ul className="aasg-list">
          {(aasg.Z || []).map((z, i) => (
            <li key={i} className="aasg-zone-item">
              <span className="zone-dot" />
              <span>{typeof z === "string" ? z : (z.name || z.id)}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Vertices */}
      <div className="card animate-in">
        <div className="aasg-section-title"><Eye size={11} />Vertices (V = S ∪ O) — {aasg.V?.length || 0} total</div>
        <ul className="aasg-list">
          {subjects.map((v, i) => (
            <li key={`s-${i}`} className="aasg-vertex-item is-subject">
              <div className="vertex-header">
                <span className="badge badge-subject">S</span>
                <span className="vertex-id">{v.id}</span>
              </div>
              <div className="vertex-meta">θ = {v.label?.theta || "external_transit"}</div>
            </li>
          ))}
          {objects.map((v, i) => (
            <li key={`o-${i}`} className="aasg-vertex-item is-object">
              <div className="vertex-header">
                <span className="badge badge-object">O</span>
                <span className="vertex-id">{v.id}</span>
              </div>
              <div className="vertex-meta">θ = {v.label?.theta || "unassigned_zone"} · type = {v.label?.type || "unknown"}</div>
            </li>
          ))}
        </ul>
      </div>

      {/* Authorization Edges Ea */}
      <div className="card animate-in">
        <div className="aasg-section-title" style={{ color: "#f59e0b" }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--ea-color)", display: "inline-block" }} />
          Authorization Edges E<sub>a</sub> ({ea.length}) — subject → object
        </div>
        <p className="hint" style={{ marginBottom: 6 }}>Actions are edge labels, not graph nodes. Role provenance explains each permission.</p>
        {ea.length === 0 ? (
          <p className="hint">No authorization edges. Upload an RBAC file to generate Ea.</p>
        ) : (
          <ul className="aasg-list">
            {ea.map((e, i) => {
              const l = e.label || {};
              return (
                <li key={i} className="aasg-edge-item is-ea">
                  <div className="edge-flow">
                    <span className="edge-node">{e.source}</span>
                    <span className="edge-arrow">→</span>
                    <span className="edge-node">{e.target}</span>
                    <span className="edge-label-pill ea-pill">{l.action || "access"}</span>
                  </div>
                  <div className="edge-meta">
                    role: {l.role_provenance || e.source} · {l.source_zone || "?"} → {l.target_zone || "?"}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* Communication Edges Ec */}
      <div className="card animate-in">
        <div className="aasg-section-title" style={{ color: "#64748b" }}>
          <span style={{ width: 8, height: 2, borderRadius: 1, background: "var(--ec-color)", display: "inline-block" }} />
          Communication Edges E<sub>c</sub> ({ec.length}) — object → object
        </div>
        <p className="hint" style={{ marginBottom: 6 }}>Architecture connections filtered by firewall rules. Protocol is the edge label.</p>
        {ec.length === 0 ? (
          <p className="hint">No communication edges found in the architecture.</p>
        ) : (
          <ul className="aasg-list">
            {ec.map((e, i) => {
              const l = e.label || {};
              return (
                <li key={i} className="aasg-edge-item is-ec">
                  <div className="edge-flow">
                    <span className="edge-node">{e.source}</span>
                    <span className="edge-arrow">→</span>
                    <span className="edge-node">{e.target}</span>
                    <span className="edge-label-pill ec-pill">{l.protocol || "unknown"}{l.port ? `:${l.port}` : ""}</span>
                  </div>
                  <div className="edge-meta">
                    {l.source_zone || "?"} → {l.target_zone || "?"} · type: {l.destination_type || "unknown"}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* Actions R catalogue */}
      {(aasg.R || []).length > 0 && (
        <div className="card animate-in">
          <div className="aasg-section-title"><Activity size={11} />Actions (R) — Catalogue</div>
          <div className="actions-wrap">
            {aasg.R.map((a, i) => (
              <span key={i} className="rbac-action-item">{a.name || a.id || a}</span>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Main App
// ---------------------------------------------------------------------------
function App() {
  const [text, setText]             = useState("vendor_operator connects to vendor_vpn. vendor_vpn connects to Master SCADA Server. Master SCADA Server connects to Turbine HMI. Turbine HMI connects to PLC_Unit_1.");
  const [archFile, setArchFile]     = useState(null);
  const [rbacFile, setRbacFile]     = useState(null);
  const [firewallFile, setFirewallFile] = useState(null);
  const [message, setMessage]       = useState("Upload files to begin AASG extraction.");
  const [loading, setLoading]       = useState(false);
  const [analysis, setAnalysis]     = useState(null);
  const [viewMode, setViewMode]     = useState("asset");
  const [activeTab, setActiveTab]   = useState("inputs");
  const [activePathIndex, setActivePathIndex] = useState(-1);
  const [blastNode, setBlastNode]   = useState(null);
  const [blastReport, setBlastReport] = useState(null);

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const onConnect = useCallback((p) => setEdges((eds) => addEdge(p, eds)), [setEdges]);

  // ---------------------------------------------------------------------------
  // Render graph
  // ---------------------------------------------------------------------------
  const applyView = useCallback(() => {
    if (!analysis) return;

    if (viewMode === "zone") {
      const rawNodes = (analysis.react_flow_macro_zone_view?.nodes || []).map((n) => ({
        ...n,
        style: {
          background: "#0d1c34", border: "2px solid #3b82f6",
          color: "#f0f6ff", borderRadius: 12, padding: 16,
          fontSize: 13, fontWeight: 700, textAlign: "center", width: 180,
        },
      }));
      const rawEdges = (analysis.react_flow_macro_zone_view?.edges || []).map((e) => ({
        ...e, animated: false,
        markerEnd: { type: MarkerType.ArrowClosed, color: "#3b82f6" },
        style: { stroke: "#3b82f6", strokeWidth: 2 },
      }));
      setNodes(layoutGraph(rawNodes, rawEdges));
      setEdges(rawEdges);
      return;
    }

    const baseNodes = JSON.parse(JSON.stringify(analysis.react_flow_asset_view?.nodes || []));
    const baseEdges = JSON.parse(JSON.stringify(analysis.react_flow_asset_view?.edges || []));

    let pathNodeIds   = new Set();
    let pathEdgePairs = new Set();

    if (activePathIndex >= 0 && analysis.attack_paths?.[activePathIndex]) {
      const p = analysis.attack_paths[activePathIndex].path;
      pathNodeIds = new Set(p);
      for (let i = 0; i < p.length - 1; i++) pathEdgePairs.add(`${p[i]}->${p[i+1]}`);
    }

    const blastIds = new Set([
      ...(blastReport?.exposed_entities?.critical_assets || []),
      ...(blastReport?.exposed_entities?.physical_processes || []),
    ]);

    const renderedNodes = baseNodes.map((n) => {
      if (n.type === "icsNode") {
        return {
          ...n,
          data: {
            ...n.data,
            onBlastRadius:       handleBlastRadius,
            in_attack_path:      pathNodeIds.has(n.id),
            is_exposed_blast:    blastIds.has(n.id) || (blastReport && n.id === blastNode),
            is_compromised_source: blastNode && n.id === blastNode,
          },
        };
      }
      return { ...n, style: { width: n.style?.width, height: n.style?.height } };
    });

    const renderedEdges = baseEdges.map((e) => {
      const key    = `${e.source}->${e.target}`;
      const inPath = pathEdgePairs.has(key);
      const faded  = activePathIndex >= 0 && !inPath;
      const label  = e.data?.label || "";

      const color = inPath
        ? "#ef4444"
        : faded
        ? "rgba(51,65,85,0.12)"
        : "rgba(71,85,105,0.5)";

      return {
        ...e,
        type: "smoothstep",
        label: label,
        labelStyle: { fill: faded ? "rgba(100,116,139,0.3)" : "#64748b", fontSize: 8, fontWeight: 600, fontFamily: "'JetBrains Mono', monospace" },
        labelBgPadding: [4, 3],
        labelBgBorderRadius: 4,
        labelBgStyle: { fill: "#060d1a", fillOpacity: faded ? 0.15 : 0.9, stroke: "rgba(51,65,85,0.5)", strokeWidth: 1 },
        animated: false,
        style: { stroke: color, strokeWidth: inPath ? 2.5 : faded ? 0.6 : 1.2, opacity: faded ? 0.35 : 1 },
        markerEnd: { type: MarkerType.ArrowClosed, color, width: inPath ? 14 : 10, height: inPath ? 14 : 10 },
      };
    });

    setNodes(renderedNodes);
    setEdges(renderedEdges);
  }, [analysis, viewMode, activePathIndex, blastNode, blastReport]);

  useEffect(() => { applyView(); }, [applyView]);

  // ---------------------------------------------------------------------------
  // Blast radius
  // ---------------------------------------------------------------------------
  const handleBlastRadius = async (nodeId) => {
    if (!analysis?.raw_model_data) return;
    try {
      setMessage(`Computing blast radius for: ${nodeId}…`);
      const res = await axios.post(`${API_URL}/blast-radius`, {
        graph_data: analysis.raw_model_data,
        node_id: nodeId,
      });
      if (res.data.error) { setMessage(res.data.error); return; }
      setBlastNode(nodeId);
      setBlastReport(res.data);
      setActivePathIndex(-1);
      setActiveTab("impact");
      setMessage(`Blast radius complete for: ${nodeId}`);
    } catch (err) {
      setMessage(`Blast radius failed: ${err.message}`);
    }
  };

  const clearBlast = () => { setBlastNode(null); setBlastReport(null); };

  // ---------------------------------------------------------------------------
  // Response handler
  // ---------------------------------------------------------------------------
  const handleResponse = (data) => {
    setAnalysis(data);
    setActivePathIndex(-1);
    clearBlast();

    if (data.validation_report && !data.validation_report.is_valid) {
      setActiveTab("audit");
      setMessage("Analysis complete. Structural errors detected.");
    } else if (data.attack_paths?.length > 0) {
      setActiveTab("vectors");
      setMessage(`Analysis complete — ${data.attack_paths.length} risk vector(s) found.`);
    } else {
      setActiveTab("aasg");
      setMessage("Analysis complete. Formal AASG model built successfully.");
    }
  };

  // ---------------------------------------------------------------------------
  // Upload handler
  // ---------------------------------------------------------------------------
  const generateFromFile = async () => {
    if (!archFile) { setMessage("Please select an Architecture Diagram first."); return; }
    try {
      setLoading(true);
      setMessage("Running Phase 1 extraction: RBAC → Firewall → Architecture → Unified Model…");
      const fd = new FormData();
      fd.append("architecture_file", archFile);
      if (rbacFile)     fd.append("rbac_file", rbacFile);
      if (firewallFile) fd.append("firewall_file", firewallFile);

      const res = await axios.post(`${API_URL}/upload`, fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      res.data.error ? setMessage(res.data.error) : handleResponse(res.data);
    } catch (err) {
      setMessage(err.message || "Upload failed");
    } finally {
      setLoading(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Text input handler (alternative architecture source)
  // ---------------------------------------------------------------------------
  const generateFromText = async () => {
    if (!text.trim()) { setMessage("No architecture text provided."); return; }
    try {
      setLoading(true);
      setMessage("Building model from text description…");
      const res = await axios.post(`${API_URL}/generate-from-text`, { text }, {
        headers: { "Content-Type": "application/json" },
      });
      res.data.error ? setMessage(res.data.error) : handleResponse(res.data);
    } catch (err) {
      setMessage(err.message || "Backend error");
    } finally {
      setLoading(false);
    }
  };

  const downloadJson = () => {
    if (!analysis) return;
    const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "aasg-model.json";
    a.click();
  };

  // ---------------------------------------------------------------------------
  // UI helpers
  // ---------------------------------------------------------------------------
  const tabDef = [
    { id: "inputs",    label: "Inputs",     icon: Upload,      alwaysOn: true },
    { id: "audit",     label: "Audit",      icon: AlertTriangle },
    { id: "vectors",   label: "Risk Vectors", icon: ShieldAlert },
    { id: "impact",    label: "Impact",     icon: Zap },
    { id: "rbac",      label: "RBAC",       icon: UserCheck },
    { id: "firewall",  label: "Firewall",   icon: Network },
    { id: "aasg",      label: "AASG",       icon: GitBranch },
  ];

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  return (
    <div className="app">
      {/* ── Sidebar ──────────────────────────────────────────────────── */}
      <aside className="sidebar">
        {/* Brand */}
        <div className="brand">
          <div className="brand-icon"><Shield size={20} /></div>
          <div className="brand-text">
            <h1>ICS AASG Analyzer</h1>
            <p>Authorization Attack Surface Graph · ISA-62443</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="tab-nav">
          {tabDef.map((t) => (
            <button
              key={t.id}
              className={`tab-btn ${activeTab === t.id ? "active" : ""}`}
              onClick={() => setActiveTab(t.id)}
              disabled={!t.alwaysOn && !analysis}
              title={t.label}
            >
              {t.label}
            </button>
          ))}
        </div>
        <div className="tab-divider" />

        {/* ── TAB: Inputs ─────────────────────────────────────────── */}
        {activeTab === "inputs" && (
          <div className="tab-content">
            {/* File Upload */}
            <div className="card">
              <div className="card-title"><Upload size={14} /> Phase 1 Data Sources</div>
              <p className="hint">Upload three input files. RBAC is the authoritative source for subjects and permissions.</p>

              <div className="file-group">
                <label className="file-label">
                  <span className="file-label-text">1. Architecture Diagram (Image / PDF) *</span>
                  <div className={`drop-zone ${archFile ? "has-file" : ""}`}>
                    <input type="file" accept=".png,.jpg,.jpeg,.webp,.pdf" onChange={(e) => setArchFile(e.target.files[0])} />
                    <Cpu size={14} className="drop-zone-icon" />
                    <span className="drop-zone-text">{archFile ? archFile.name : "Select architecture diagram"}</span>
                  </div>
                </label>
              </div>

              <div className="file-group">
                <label className="file-label">
                  <span className="file-label-text">2. RBAC Policy File (JSON / CSV / TXT / YAML)</span>
                  <div className={`drop-zone secondary ${rbacFile ? "has-file" : ""}`}>
                    <input type="file" accept=".json,.csv,.txt,.yaml,.yml" onChange={(e) => setRbacFile(e.target.files[0])} />
                    <Lock size={14} className="drop-zone-icon" />
                    <span className="drop-zone-text">{rbacFile ? rbacFile.name : "Subjects · Actions · Permissions"}</span>
                  </div>
                </label>
              </div>

              <div className="file-group">
                <label className="file-label">
                  <span className="file-label-text">3. Firewall Rules File (JSON)</span>
                  <div className={`drop-zone secondary ${firewallFile ? "has-file" : ""}`}>
                    <input type="file" accept=".json" onChange={(e) => setFirewallFile(e.target.files[0])} />
                    <Network size={14} className="drop-zone-icon" />
                    <span className="drop-zone-text">{firewallFile ? firewallFile.name : "Constrains Ec edges (JSON)"}</span>
                  </div>
                </label>
              </div>

              <button className="btn btn-primary" onClick={generateFromFile} disabled={loading || !archFile}>
                {loading ? <RefreshCw size={14} className="animate-spin" /> : <ChevronRight size={14} />}
                {loading ? "Extracting…" : "Run Phase 1 Extraction"}
              </button>
            </div>

            {/* Text input — alternative architecture source */}
            <SectionSep label="or" />
            <div className="card">
              <div className="card-title"><FileText size={14} /> Text Architecture Description</div>
              <p className="hint">Alternative architecture source. Describe connections as text. Produces the same A={'{'}Z,E,S,O,R{'}'} structure.</p>
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder="e.g. vendor_vpn connects to scada_server. scada_server connects to turbine_plc."
              />
              <button className="btn btn-secondary" onClick={generateFromText} disabled={loading}>
                {loading ? <RefreshCw size={14} className="animate-spin" /> : <FileText size={14} />}
                Parse Text Architecture
              </button>
            </div>

            {/* Model summary after analysis */}
            {analysis?.raw_model_data && (
              <div className="card animate-in">
                <div className="card-title"><Database size={14} /> Unified Model A = {'{'}Z, E, S, O, R{'}'}</div>
                <div className="stat-grid">
                  <div className="stat-cell">
                    <span className="stat-val" style={{ color: "var(--accent-bright)" }}>{analysis.raw_model_data.Z?.length || analysis.raw_model_data.zones?.length || 0}</span>
                    <span className="stat-label">Zones (Z)</span>
                  </div>
                  <div className="stat-cell">
                    <span className="stat-val" style={{ color: "var(--subject-color)" }}>{analysis.raw_model_data.S?.length || analysis.raw_model_data.roles?.length || 0}</span>
                    <span className="stat-label">Subjects (S)</span>
                  </div>
                  <div className="stat-cell">
                    <span className="stat-val" style={{ color: "var(--object-color)" }}>{analysis.raw_model_data.O?.length || analysis.raw_model_data.assets?.length || 0}</span>
                    <span className="stat-label">Objects (O)</span>
                  </div>
                  <div className="stat-cell">
                    <span className="stat-val" style={{ color: "var(--ea-color)" }}>{analysis.raw_model_data.R?.length || 0}</span>
                    <span className="stat-label">Actions (R)</span>
                  </div>
                </div>
                <div className="stat-divider" />
                <div className="stat-subrow">
                  <div>Auth Edges E<sub>a</sub>: <strong>{analysis.raw_model_data.permissions?.length || 0}</strong></div>
                  <div>Comm Edges E<sub>c</sub>: <strong>{analysis.raw_model_data.communications?.length || 0}</strong></div>
                </div>
                {analysis.raw_model_data.firewall_blocked?.length > 0 && (
                  <div style={{ marginTop: 8, fontSize: 10, color: "var(--warning)", display: "flex", alignItems: "center", gap: 5 }}>
                    <ShieldAlert size={11} />
                    {analysis.raw_model_data.firewall_blocked.length} connection(s) blocked by firewall policy
                  </div>
                )}
                <button className="btn btn-secondary" style={{ marginTop: 10 }} onClick={downloadJson}>Download Full JSON</button>
              </div>
            )}
          </div>
        )}

        {/* ── TAB: Audit ──────────────────────────────────────────── */}
        {activeTab === "audit" && analysis && (
          <div className="tab-content animate-in">
            <div className="card">
              <div className="card-title"><Shield size={14} /> Architecture Health</div>
              <div className="health-score">
                <div className={`health-number ${analysis.validation_report.is_valid ? "ok" : "bad"}`}>
                  {analysis.validation_report.is_valid ? "✓" : "✗"}
                </div>
                <div className="health-label">
                  {analysis.validation_report.is_valid ? "Graph is structurally valid" : "Structural errors detected"}
                </div>
              </div>
            </div>

            <div className="card">
              <div className="card-title"><AlertTriangle size={14} style={{ color: "var(--danger)" }} /> Errors ({analysis.validation_report.errors.length})</div>
              {analysis.validation_report.errors.length === 0
                ? <p className="audit-ok"><CheckCircle size={12} /> No errors detected.</p>
                : <ul className="audit-list">{analysis.validation_report.errors.map((e, i) => <li key={i} className="audit-error-item">{e}</li>)}</ul>
              }
            </div>

            <div className="card">
              <div className="card-title"><ShieldAlert size={14} style={{ color: "var(--warning)" }} /> Warnings ({analysis.validation_report.warnings.length})</div>
              {analysis.validation_report.warnings.length === 0
                ? <p className="audit-ok"><CheckCircle size={12} /> No warnings.</p>
                : <ul className="audit-list">{analysis.validation_report.warnings.map((w, i) => <li key={i} className="audit-warning-item">{w}</li>)}</ul>
              }
            </div>

            {analysis.raw_model_data?.validation_issues?.length > 0 && (
              <div className="card">
                <div className="card-title"><AlertTriangle size={14} style={{ color: "#eab308" }} /> Model Validation Issues</div>
                <ul className="audit-list">
                  {analysis.raw_model_data.validation_issues.map((v, i) => (
                    <li key={i} className="audit-warning-item">{v}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* ── TAB: Risk Vectors ───────────────────────────────────── */}
        {activeTab === "vectors" && analysis && (
          <div className="tab-content animate-in">
            <div className="card">
              <div className="card-title"><ShieldAlert size={14} /> Risk Vectors</div>
              <p className="hint">Authorization-driven attack paths from entry subjects to critical objects:</p>
              {(!analysis.attack_paths || analysis.attack_paths.length === 0)
                ? <EmptyState icon={CheckCircle} message="No risk vectors found." />
                : (
                  <div className="paths-list">
                    {analysis.attack_paths.map((path, idx) => (
                      <div
                        key={idx}
                        className={`path-item ${activePathIndex === idx ? "selected" : ""}`}
                        onClick={() => { clearBlast(); setActivePathIndex(activePathIndex === idx ? -1 : idx); }}
                      >
                        <div className="path-meta">
                          <span className="path-idx">Vector #{idx + 1}</span>
                          <span className="path-risk">Risk: {path.overall_risk}</span>
                        </div>
                        <div className="path-details">
                          <span>Impact: {path.impact_score}</span>
                          <span>Likelihood: {Math.round(path.likelihood_score * 100)}%</span>
                        </div>
                        <div className="path-chain">{path.path.join(" → ")}</div>
                      </div>
                    ))}
                  </div>
                )
              }
            </div>

            {activePathIndex >= 0 && analysis.attack_paths?.[activePathIndex] && (
              <div className="card narrative-card animate-in">
                <div className="card-title"><Activity size={14} /> Analyst Narrative</div>
                <div className="narrative-body">
                  {analysis.attack_paths[activePathIndex].narrative.split("\n\n").map((p, i) => <p key={i}>{p}</p>)}
                  {analysis.attack_paths[activePathIndex].realism_warnings?.length > 0 && (
                    <div className="realism-box">
                      <strong>Architecture Warnings:</strong>
                      <ul>{analysis.attack_paths[activePathIndex].realism_warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── TAB: Impact Analysis ────────────────────────────────── */}
        {activeTab === "impact" && analysis && (
          <div className="tab-content animate-in">
            <div className="card">
              <div className="card-title"><Zap size={14} /> Compromise Blast Radius</div>
              {!blastNode
                ? <div className="blast-empty"><Terminal size={28} /><p>Click the <strong>Impact</strong> button on any node in the graph to compute its blast radius.</p></div>
                : (
                  <>
                    <div className="blast-header">
                      <span className="blast-node-name">{blastNode}</span>
                      <button className="btn btn-ghost" onClick={clearBlast}>Clear</button>
                    </div>
                    {blastReport && (
                      <>
                        <div className="blast-stats">
                          <div className="blast-stat">
                            <span className="num">{blastReport.operational_summary.total_assets_exposed}</span>
                            <span className="lbl">Assets Exposed</span>
                          </div>
                          <div className="blast-stat">
                            <span className="num">{blastReport.operational_summary.critical_assets_exposed}</span>
                            <span className="lbl">Critical Cyber</span>
                          </div>
                          <div className="blast-stat">
                            <span className="num">{blastReport.operational_summary.physical_processes_exposed}</span>
                            <span className="lbl">Physics Lost</span>
                          </div>
                        </div>
                        {blastReport.exposed_entities?.critical_assets?.length > 0 && (
                          <div className="blast-list">
                            <h4>Exposed Critical Cyber:</h4>
                            <ul>{blastReport.exposed_entities.critical_assets.map((a, i) => <li key={i}>{a}</li>)}</ul>
                          </div>
                        )}
                        {blastReport.exposed_entities?.physical_processes?.length > 0 && (
                          <div className="blast-list" style={{ marginTop: 8 }}>
                            <h4>Compromised Physical:</h4>
                            <ul>{blastReport.exposed_entities.physical_processes.map((p, i) => <li key={i}>{p}</li>)}</ul>
                          </div>
                        )}
                      </>
                    )}
                  </>
                )
              }
            </div>

            <div className="card">
              <div className="card-title"><GitBranch size={14} /> Cyber-Physical Exposure Vectors</div>
              {(!analysis.reachability_data?.cyber_physical_vectors?.length)
                ? <p className="audit-ok"><CheckCircle size={12} /> No direct cyber-physical exposure paths.</p>
                : (
                  <ul className="vector-list">
                    {analysis.reachability_data.cyber_physical_vectors.map((v, i) => (
                      <li key={i} className="vector-item">
                        <div className="vec-title">{v.source} → {v.target}</div>
                        <div className="vec-meta"><span>Confidence: {v.confidence}</span><span>{v.path_length} hops</span></div>
                        <div className="vec-summary">{v.explanation?.summary}</div>
                      </li>
                    ))}
                  </ul>
                )
              }
            </div>
          </div>
        )}

        {/* ── TAB: RBAC Summary ───────────────────────────────────── */}
        {activeTab === "rbac" && analysis && (
          <div className="tab-content animate-in">
            <RBACTab
              rbacSummary={analysis.rbac_summary}
              permissions={analysis.raw_model_data?.permissions}
            />
          </div>
        )}

        {/* ── TAB: Firewall ───────────────────────────────────────── */}
        {activeTab === "firewall" && analysis && (
          <div className="tab-content animate-in">
            <FirewallTab
              firewallSummary={analysis.firewall_summary}
              firewallBlocked={analysis.raw_model_data?.firewall_blocked}
            />
          </div>
        )}

        {/* ── TAB: AASG Model ─────────────────────────────────────── */}
        {activeTab === "aasg" && analysis && (
          <div className="tab-content animate-in">
            <AASGTab aasg={analysis.aasg} />
          </div>
        )}

        {/* System Log */}
        <div className="system-log">
          <div className="log-header">
            <span className="log-title">System Log</span>
            {analysis && (
              <button className="btn btn-ghost" style={{ padding: "2px 8px", fontSize: "9px" }} onClick={downloadJson}>
                Export JSON
              </button>
            )}
          </div>
          <div className="log-text">{message}</div>
        </div>
      </aside>

      {/* ── Canvas ────────────────────────────────────────────────── */}
      <main className="canvas">
        {analysis && (
          <div className="canvas-toolbar">
            <div className="view-toggle">
              <button className={viewMode === "asset" ? "active" : ""} onClick={() => setViewMode("asset")}>
                <Cpu size={13} /> Asset View
              </button>
              <button className={viewMode === "zone" ? "active" : ""} onClick={() => setViewMode("zone")}>
                <Compass size={13} /> Zone View
              </button>
            </div>
            <div className="canvas-legend">
              <span className="legend-hint">Scroll: Pan · Ctrl+Scroll: Zoom</span>
              <div className="legend-sep" />
              <div className="legend-item"><span className="legend-dot" style={{ background: "var(--crit-critical)" }} />Critical</div>
              <div className="legend-item"><span className="legend-dot" style={{ background: "var(--crit-high)" }} />High</div>
              <div className="legend-sep" />
              <div className="legend-item"><span className="legend-line" style={{ background: "var(--ea-color)" }} />Auth (E<sub>a</sub>)</div>
              <div className="legend-item"><span className="legend-line" style={{ background: "var(--ec-color)" }} />Comm (E<sub>c</sub>)</div>
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
          fitViewOptions={{ padding: 0.15, minZoom: 0.1, maxZoom: 1.5 }}
          minZoom={0.06}
          maxZoom={2.5}
          panOnScroll
          panOnScrollMode="free"
          zoomOnScroll={false}
          defaultEdgeOptions={{
            type: "smoothstep",
            animated: false,
            style: { stroke: "rgba(71,85,105,0.5)", strokeWidth: 1.2 },
            markerEnd: { type: MarkerType.ArrowClosed, color: "rgba(71,85,105,0.5)", width: 10, height: 10 },
          }}
        >
          <Background variant={BackgroundVariant.Dots} color="rgba(30,41,59,0.4)" gap={28} size={1.2} />
          <Controls showInteractive={false} />
          <MiniMap
            nodeColor={(n) => typeColors[n.data?.type || n.type] || "#0d1c34"}
            maskColor="rgba(3,8,16,0.75)"
            style={{ background: "rgba(5,13,26,0.9)" }}
          />
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