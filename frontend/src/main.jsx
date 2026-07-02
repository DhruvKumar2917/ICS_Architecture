import React, { useCallback, useState, useEffect, memo } from "react";
import { createRoot } from "react-dom/client";
import ReactFlow, {
  Background, BackgroundVariant, Controls, MiniMap, Panel,
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
  firewall: "#e2e8f0", server: "#fef08a", database: "#e2e8f0",
  vpn: "#e2e8f0", plc: "#fee2e2", scada: "#fef08a",
  zone: "#fafafa", user: "#dbeafe", subject: "#dbeafe",
  object: "#f1f5f9", component: "#ffffff",
};

// Helper to resolve colors and styles based on Purdue levels
const getPurdueTheme = (level) => {
  const lvl = String(level || "").toLowerCase();
  if (lvl.includes("level 4") || lvl.includes("level 5")) {
    return {
      bg: "#eff6ff", // light blue
      border: "#3b82f6",
      text: "#1e3a8a",
      badgeBg: "#dbeafe",
      badgeText: "#1e40af",
    };
  }
  if (lvl.includes("level 3")) {
    return {
      bg: "#fef8e7", // light amber
      border: "#eab308",
      text: "#713f12",
      badgeBg: "#fef08a",
      badgeText: "#854d0e",
    };
  }
  if (lvl.includes("level 2")) {
    return {
      bg: "#fff7ed", // light orange
      border: "#ea580c",
      text: "#7c2d12",
      badgeBg: "#ffedd5",
      badgeText: "#9a3412",
    };
  }
  if (lvl.includes("level 1") || lvl.includes("level 0")) {
    return {
      bg: "#fef2f2", // light red
      border: "#ef4444",
      text: "#7f1d1d",
      badgeBg: "#fee2e2",
      badgeText: "#991b1b",
    };
  }
  return {
    bg: "#f8fafc", // slate
    border: "#64748b",
    text: "#0f172a",
    badgeBg: "#e2e8f0",
    badgeText: "#334155",
  };
};

// ---------------------------------------------------------------------------
// Custom ICS Node
// ---------------------------------------------------------------------------
const ICSNode = memo(({ data }) => {
  const criticality = data.criticality || "medium";
  const purdueLevel = data.purdue_level || "";
  const type = data.type || "component";
  const inAttackPath = data.in_attack_path;
  const isEnforcement = data.is_enforcement_point;
  const isExposedBlast = data.is_exposed_blast;
  const isCompromised = data.is_compromised_source;

  // New infection and lateral movement fields
  const isInfected = data.is_infected;
  const isInfectionOrigin = data.is_infection_origin;
  const inLateralPath = data.in_lateral_path;
  const isLatEventSource = data.is_lateral_event_source;
  const isLatEventTarget = data.is_lateral_event_target;

  const purdueTheme = getPurdueTheme(purdueLevel);
  
  let customBg = purdueTheme.bg;
  let customBorderColor = purdueTheme.border;
  let glow = "none";
  let borderWidth = "1.5px";

  if (isInfectionOrigin) {
    customBg = "#dcfce7";
    customBorderColor = "#22c55e";
    glow = "0 0 15px rgba(34, 197, 94, 0.45)";
    borderWidth = "2.5px";
  } else if (isInfected) {
    customBg = "#f0fdf4";
    customBorderColor = "#4ade80";
    glow = "0 0 10px rgba(74, 222, 128, 0.3)";
    borderWidth = "2px";
  } else if (isCompromised) {
    customBg = "#fee2e2";
    customBorderColor = "#ef4444";
    glow = "0 0 15px rgba(239, 68, 68, 0.45)";
    borderWidth = "2.5px";
  } else if (inAttackPath) {
    customBg = "#fff5f5";
    customBorderColor = "#dc2626";
    glow = "0 0 15px rgba(220, 38, 38, 0.45)";
    borderWidth = "2.5px";
  } else if (inLateralPath) {
    customBg = "#fffaf0";
    customBorderColor = "#f97316";
    glow = "0 0 12px rgba(249, 115, 22, 0.35)";
    borderWidth = "2px";
  } else if (isExposedBlast) {
    customBg = "#fef3c7";
    customBorderColor = "#f59e0b";
    glow = "0 0 10px rgba(245, 158, 11, 0.3)";
    borderWidth = "2px";
  } else if (isLatEventSource || isLatEventTarget) {
    customBg = "#fffaf0";
    customBorderColor = "#f97316";
    glow = "0 0 12px rgba(249, 115, 22, 0.35)";
    borderWidth = "2.5px";
  } else if (criticality === "critical" || criticality === "high") {
    borderWidth = "2px";
  }

  return (
    <div
      className={`ics-node ${inAttackPath || isLatEventSource || isLatEventTarget ? "pulse-red" : isInfected ? "pulse-green" : inLateralPath ? "pulse-orange" : ""}`}
      title={[
        `${(data.label || "Asset")}`,
        `Type: ${type}`,
        `Criticality: ${criticality}`,
        `Zone: ${data.zone || "—"}`,
        `Purdue: ${purdueLevel || "—"}`,
        data.security_role ? `Role: ${data.security_role}` : null,
        (data.risk_score != null) ? `Risk: ${Number(data.risk_score).toFixed(1)}` : null,
        (data._protocols && data._protocols.length) ? `Protocols: ${data._protocols.join(", ")}` : null,
      ].filter(Boolean).join("\n")}
      style={{ 
        borderColor: customBorderColor, 
        backgroundColor: customBg,
        boxShadow: glow, 
        borderWidth: borderWidth
      }}
    >
      <Handle type="target" position={Position.Top} className="node-handle" />

      <div className="ics-node-header">
        <span className="ics-node-type">{type.toUpperCase()}</span>
        {purdueLevel && purdueLevel !== "unknown" && (
          <span className="ics-node-purdue" style={{ backgroundColor: purdueTheme.badgeBg, color: purdueTheme.badgeText, borderColor: purdueTheme.border }}>
            {purdueLevel}
          </span>
        )}
      </div>

      <div className="ics-node-name">{data.label || "Asset"}</div>

      {data.active_mitre && (
        <div className="ics-node-mitre-overlay" title={`${data.active_mitre.id}: ${data.active_mitre.name}`}>
          <Shield size={9} style={{ color: "#b91c1c" }} />
          <span>{data.active_mitre.id}</span>
        </div>
      )}

      <div className="ics-node-footer">
        {criticality === "critical" && <span className="badge badge-critical">CRITICAL</span>}
        {isEnforcement && <span className="badge badge-enforce">SECURE</span>}
        {isCompromised && <span className="badge badge-subject">COMPROMISED</span>}
        {isExposedBlast && !isCompromised && <span className="badge badge-exposed">EXPOSED</span>}
        {isInfectionOrigin && <span className="badge badge-subject">PATIENT ZERO</span>}
        {isInfected && !isInfectionOrigin && <span className="badge badge-allowed">INFECTED</span>}
        {inLateralPath && <span className="badge badge-exposed">LATERAL</span>}
        {(isLatEventSource || isLatEventTarget) && <span className="badge badge-blocked">PIVOT</span>}
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
  const subjects = rbacSummary?.S || [];
  const actions = rbacSummary?.R || [];
  const perms = rbacSummary?.permissions || permissions || [];
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
  const rules = firewallSummary?.rules || [];
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
  const denied = rules.filter((r) => !["allow", "accept", "permit", "pass"].includes(r.action));

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

  const subjects = (aasg.V || []).filter((v) => v.vertex_type === "subject");
  const objects = (aasg.V || []).filter((v) => v.vertex_type === "object");
  const ea = aasg.E?.E_a || [];
  const ec = aasg.E?.E_c || [];
  const stats = aasg.stats || {};

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
        <div className="aasg-section-title">
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
        <div className="aasg-section-title">
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
  const [text, setText] = useState("vendor_operator connects to vendor_vpn. vendor_vpn connects to Master SCADA Server. Master SCADA Server connects to Turbine HMI. Turbine HMI connects to PLC_Unit_1.");
  const [archFile, setArchFile] = useState(null);
  const [rbacFile, setRbacFile] = useState(null);
  const [firewallFile, setFirewallFile] = useState(null);
  const [message, setMessage] = useState("Upload files to begin AASG extraction.");
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [viewMode, setViewMode] = useState("asset");
  const [activeTab, setActiveTab] = useState("inputs");
  const [activePathIndex, setActivePathIndex] = useState(-1);
  const [blastNode, setBlastNode] = useState(null);
  const [blastReport, setBlastReport] = useState(null);

  // Threat propagation states
  const [activePropNode, setActivePropNode] = useState(null);
  const [propDepth, setPropDepth] = useState(0);

  // Lateral movement states
  const [activeLatChainIndex, setActiveLatChainIndex] = useState(-1);
  const [activeLatEventIndex, setActiveLatEventIndex] = useState(-1);

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const onConnect = useCallback((p) => setEdges((eds) => addEdge(p, eds)), [setEdges]);

  // Search and Zone filtering states
  const [searchQuery, setSearchQuery] = useState("");
  const [zoneFilter, setZoneFilter] = useState("all");

  const prevAnalysisRef = React.useRef(null);
  const prevViewModeRef = React.useRef(null);

  // ---------------------------------------------------------------------------
  // Render graph
  // ---------------------------------------------------------------------------
  const applyView = useCallback(() => {
    if (!analysis) return;

    if (viewMode === "zone") {
      const rawNodes = (analysis.react_flow_macro_zone_view?.nodes || []).map((n) => ({
        ...n,
        style: {
          background: "#ffffff", border: "2px solid #000000",
          color: "#000000", borderRadius: 12, padding: 16,
          fontSize: 13, fontWeight: 700, textAlign: "center", width: 180,
        },
      }));
      const rawEdges = (analysis.react_flow_macro_zone_view?.edges || []).map((e) => ({
        ...e, animated: false,
        markerEnd: { type: MarkerType.ArrowClosed, color: "#000000" },
        style: { stroke: "#000000", strokeWidth: 1.5 },
      }));
      setNodes(layoutGraph(rawNodes, rawEdges));
      setEdges(rawEdges);
      return;
    }

    const baseNodes = analysis.react_flow_asset_view?.nodes || [];
    const baseEdges = analysis.react_flow_asset_view?.edges || [];

    const isLayoutReset = prevAnalysisRef.current !== analysis || prevViewModeRef.current !== viewMode;
    prevAnalysisRef.current = analysis;
    prevViewModeRef.current = viewMode;

    let pathNodeIds = new Set();
    let pathEdgePairs = new Set();
    let nodeMitreMap = new Map();
    let isFadedNode = () => false;

    // Check attack path highlighting
    if (activeTab === "vectors" && activePathIndex >= 0 && analysis.attack_paths?.[activePathIndex]) {
      const pathRec = analysis.attack_paths[activePathIndex];
      const p = pathRec.path;
      pathNodeIds = new Set(p);
      for (let i = 0; i < p.length - 1; i++) pathEdgePairs.add(`${p[i]}->${p[i + 1]}`);
      isFadedNode = (id) => !pathNodeIds.has(id);

      // Extract MITRE overlays
      const hops = pathRec.mitre_hops || [];
      hops.forEach((hop) => {
        if (hop.to) nodeMitreMap.set(hop.to, hop.mitre);
      });
    }

    // Threat Propagation highlighting
    let infectedNodeIds = new Set();
    let propEdgePairs = new Set();
    let infectionOrigin = null;
    if (activeTab === "propagation" && activePropNode && analysis.threat_propagation?.[activePropNode]) {
      const sim = analysis.threat_propagation[activePropNode];
      infectionOrigin = sim.infection_origin;
      const timeline = sim.propagation_timeline || [];
      timeline.forEach((item) => {
        if (item.depth <= propDepth) {
          infectedNodeIds.add(item.infected_node);
          if (item.from_node) {
            propEdgePairs.add(`${item.from_node}->${item.infected_node}`);
          }
        }
      });
      isFadedNode = (id) => !infectedNodeIds.has(id);
    }

    // Lateral Movement Chains/Events highlighting
    let lateralNodeIds = new Set();
    let lateralEdgePairs = new Set();
    let latEventNodes = new Set();
    if (activeTab === "lateral") {
      if (activeLatChainIndex >= 0 && analysis.lateral_movement?.high_risk_paths?.[activeLatChainIndex]) {
        const p = analysis.lateral_movement.high_risk_paths[activeLatChainIndex].path;
        lateralNodeIds = new Set(p);
        for (let i = 0; i < p.length - 1; i++) lateralEdgePairs.add(`${p[i]}->${p[i + 1]}`);
        isFadedNode = (id) => !lateralNodeIds.has(id);
      } else if (activeLatEventIndex >= 0 && analysis.lateral_movement?.movement_events?.[activeLatEventIndex]) {
        const ev = analysis.lateral_movement.movement_events[activeLatEventIndex];
        if (ev.from_node && ev.to_node) {
          latEventNodes.add(ev.from_node);
          latEventNodes.add(ev.to_node);
          lateralEdgePairs.add(`${ev.from_node}->${ev.to_node}`);
          isFadedNode = (id) => id !== ev.from_node && id !== ev.to_node;
        }
      }
    }

    const blastIds = new Set([
      ...(blastReport?.exposed_entities?.critical_assets || []),
      ...(blastReport?.exposed_entities?.physical_processes || []),
    ]);
    const isBlastActive = activeTab === "impact" && blastNode;
    if (isBlastActive) {
      isFadedNode = (id) => id !== blastNode && !blastIds.has(id);
    }

    // Dynamic filtering checks
    const searchLower = searchQuery.toLowerCase().trim();
    const isNodeFiltered = (node) => {
      if (node.type === "icsGroup") return false;

      // 1. Zone filtering
      if (zoneFilter !== "all" && node.data?.zone !== zoneFilter) {
        return true;
      }
      // 2. Search query filtering
      if (searchLower) {
        const label = String(node.data?.label || "").toLowerCase();
        const id = String(node.id).toLowerCase();
        const type = String(node.data?.type || "").toLowerCase();
        if (!label.includes(searchLower) && !id.includes(searchLower) && !type.includes(searchLower)) {
          return true;
        }
      }
      return false;
    };

    const visibleNodeIds = new Set();
    const visibleZoneGroups = new Set();
    const assetNodesOnly = baseNodes.filter(n => n.type === "icsNode");

    // Aggregate the protocols touching each node (for hover details).
    const nodeProtocols = new Map();
    baseEdges.forEach((e) => {
      const proto = e.data?.label || e.data?.protocol;
      if (!proto || e.data?.edge_type !== "COMM_LINK") return;
      [e.source, e.target].forEach((nid) => {
        if (!nodeProtocols.has(nid)) nodeProtocols.set(nid, new Set());
        nodeProtocols.get(nid).add(String(proto));
      });
    });

    assetNodesOnly.forEach((n) => {
      if (!isNodeFiltered(n)) {
        visibleNodeIds.add(n.id);
        const zoneId = n.data?.zone;
        if (zoneId) {
          visibleZoneGroups.add(`group_${zoneId}`);
        }
      }
    });

    setNodes((prevNodes) => {
      const sourceNodes = (prevNodes.length > 0 && !isLayoutReset) ? prevNodes : baseNodes;

      return sourceNodes.map((n) => {
        const faded = isFadedNode(n.id);
        const isHidden = n.type === "icsNode" ? !visibleNodeIds.has(n.id) : !visibleZoneGroups.has(n.id);

        if (n.type === "icsNode") {
          return {
            ...n,
            style: {
              ...n.style,
              opacity: faded ? 0.35 : 1,
              display: isHidden ? "none" : "flex",
              transition: "opacity 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease",
            },
            data: {
              ...n.data,
              onBlastRadius: handleBlastRadius,
              in_attack_path: activeTab === "vectors" && pathNodeIds.has(n.id),
              is_exposed_blast: isBlastActive && (blastIds.has(n.id) || n.id === blastNode),
              is_compromised_source: isBlastActive && n.id === blastNode,
              is_infected: activeTab === "propagation" && infectedNodeIds.has(n.id),
              is_infection_origin: activeTab === "propagation" && n.id === infectionOrigin,
              in_lateral_path: activeTab === "lateral" && lateralNodeIds.has(n.id),
              is_lateral_event_source: activeTab === "lateral" && latEventNodes.has(n.id) && n.id === analysis.lateral_movement?.movement_events?.[activeLatEventIndex]?.from_node,
              is_lateral_event_target: activeTab === "lateral" && latEventNodes.has(n.id) && n.id === analysis.lateral_movement?.movement_events?.[activeLatEventIndex]?.to_node,
              active_mitre: nodeMitreMap.get(n.id),
              _protocols: Array.from(nodeProtocols.get(n.id) || []),
            },
          };
        }
        return { 
          ...n, 
          style: { 
            ...n.style, 
            opacity: faded ? 0.25 : 1, 
            display: isHidden ? "none" : "block",
            transition: "opacity 0.2s ease" 
          } 
        };
      });
    });

    const renderedEdges = baseEdges.map((e) => {
      const key = `${e.source}->${e.target}`;
      const edgeType = e.data?.edge_type || "COMM_LINK";

      // Idle/base palette keyed by edge category:
      //   HUMAN_PERM (Ea, authorization)  -> purple
      //   CYBER_PHYSICAL (control->process) -> purple-red
      //   COMM_LINK (Ec, communication)   -> blue
      const idlePalette = {
        HUMAN_PERM:     "#7c3aed",  // purple
        CYBER_PHYSICAL: "#9333ea",  // violet
        COMM_LINK:      "#2563eb",  // blue
      };

      let inPath = false;
      let strokeColor = idlePalette[edgeType] || idlePalette.COMM_LINK;
      let strokeWidth = edgeType === "HUMAN_PERM" ? 1.4 : 1.2;
      let opacity = 0.55;
      let animated = false;
      let dashed = edgeType === "HUMAN_PERM";  // dash authorization edges

      if (activeTab === "vectors" && activePathIndex >= 0) {
        inPath = pathEdgePairs.has(key);
        strokeColor = inPath ? "#dc2626" : "rgba(0,0,0,0.08)";
        strokeWidth = inPath ? 3.0 : 0.6;
        opacity = inPath ? 1 : 0.35;
        animated = inPath;
      } else if (activeTab === "propagation" && activePropNode) {
        inPath = propEdgePairs.has(key);
        strokeColor = inPath ? "#22c55e" : "rgba(0,0,0,0.08)";
        strokeWidth = inPath ? 3.0 : 0.6;
        opacity = inPath ? 1 : 0.35;
        animated = inPath;
      } else if (activeTab === "lateral") {
        inPath = lateralEdgePairs.has(key);
        strokeColor = inPath ? "#f97316" : "rgba(0,0,0,0.08)";
        strokeWidth = inPath ? 3.0 : 0.6;
        opacity = inPath ? 1 : 0.35;
        animated = inPath;
      } else if (isBlastActive) {
        const isFromBlast = e.source === blastNode && blastIds.has(e.target);
        const isWithinBlast = blastIds.has(e.source) && blastIds.has(e.target);
        inPath = isFromBlast || isWithinBlast;
        strokeColor = inPath ? "#eab308" : "rgba(0,0,0,0.08)";
        strokeWidth = inPath ? 2.5 : 0.6;
        opacity = inPath ? 1 : 0.35;
        animated = inPath;
      }

      const edgeHidden = !visibleNodeIds.has(e.source) || !visibleNodeIds.has(e.target);

      const label = e.data?.label || "";
      const faded = !inPath && (
        (activeTab === "vectors" && activePathIndex >= 0) ||
        (activeTab === "propagation" && activePropNode) ||
        (activeTab === "lateral" && (activeLatChainIndex >= 0 || activeLatEventIndex >= 0)) ||
        isBlastActive
      );

      return {
        ...e,
        type: "smoothstep",
        label: label,
        labelStyle: { fill: faded ? "rgba(0,0,0,0.2)" : "#000000", fontSize: 8, fontWeight: 600, fontFamily: "'JetBrains Mono', monospace" },
        labelBgPadding: [4, 3],
        labelBgBorderRadius: 4,
        labelBgStyle: { fill: "#ffffff", fillOpacity: faded ? 0.15 : 0.9, stroke: faded ? "rgba(0,0,0,0.08)" : "rgba(0,0,0,0.2)", strokeWidth: 1 },
        animated: animated,
        style: {
          stroke: strokeColor,
          strokeWidth: strokeWidth,
          opacity: opacity,
          display: edgeHidden ? "none" : "block",
          strokeDasharray: (dashed && !inPath) ? "5 4" : undefined,
        },
        className: inPath ? "edge-attack-flow" : undefined,
        markerEnd: { type: MarkerType.ArrowClosed, color: strokeColor, width: inPath ? 14 : 10, height: inPath ? 14 : 10 },
      };
    });

    setEdges(renderedEdges);
  }, [analysis, viewMode, activePathIndex, blastNode, blastReport, activePropNode, propDepth, activeLatChainIndex, activeLatEventIndex, activeTab, searchQuery, zoneFilter]);

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
    setActiveLatChainIndex(-1);
    setActiveLatEventIndex(-1);

    // Auto-select first threat propagation node if available
    if (data.threat_propagation && Object.keys(data.threat_propagation).length > 0) {
      const firstOrigin = Object.keys(data.threat_propagation)[0];
      setActivePropNode(firstOrigin);
      setPropDepth(0);
    } else {
      setActivePropNode(null);
      setPropDepth(0);
    }

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
      if (rbacFile) fd.append("rbac_file", rbacFile);
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
    { id: "inputs", label: "Inputs", icon: Upload, alwaysOn: true },
    { id: "audit", label: "Audit", icon: AlertTriangle },
    { id: "vectors", label: "Risk Vectors", icon: ShieldAlert },
    { id: "risk", label: "Risk Assets", icon: Activity },
    { id: "mitre", label: "MITRE ATT&CK", icon: Shield },
    { id: "propagation", label: "Threat Prop", icon: Zap },
    { id: "lateral", label: "Lat Movement", icon: GitBranch },
    { id: "impact", label: "Impact", icon: Zap },
    { id: "rbac", label: "RBAC", icon: UserCheck },
    { id: "firewall", label: "Firewall", icon: Network },
    { id: "aasg", label: "AASG", icon: GitBranch },
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

        {/* ── TAB: Risk Assets ────────────────────────────────────── */}
        {activeTab === "risk" && analysis && (
          <div className="tab-content animate-in">
            <div className="card">
              <div className="card-title"><Activity size={14} /> Critical Node Risk Rankings</div>
              <p className="hint">Ranking of assets by cumulative threat propagation and lateral movement exposure:</p>
              {(!analysis.risk_analysis?.node_rankings || analysis.risk_analysis.node_rankings.length === 0)
                ? <EmptyState icon={CheckCircle} message="No node rankings available." />
                : (
                  <div className="risk-assets-list" style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 400, overflowY: "auto" }}>
                    {analysis.risk_analysis.node_rankings.map((nodeRec, idx) => {
                      const score = nodeRec.risk_score || nodeRec.score || 0;
                      const sev = nodeRec.severity || (score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 30 ? "MEDIUM" : "LOW");

                      let badgeClass = "badge-low";
                      if (sev === "CRITICAL") badgeClass = "badge-critical";
                      else if (sev === "HIGH") badgeClass = "badge-high";
                      else if (sev === "MEDIUM") badgeClass = "badge-ea";

                      return (
                        <div key={idx} className="risk-asset-item" style={{ background: "var(--bg-void)", border: "1px solid var(--border-subtle)", borderRadius: 9, padding: "8px 10px", display: "flex", flexDirection: "column", gap: 3 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700, color: "var(--text-primary)" }}>{nodeRec.node}</span>
                            <span className={`badge ${badgeClass}`}>{sev} ({score})</span>
                          </div>
                          <div style={{ display: "flex", gap: 8, fontSize: 9.5, color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                            {nodeRec.purdue_level && nodeRec.purdue_level !== "unknown" && <span>Purdue: {nodeRec.purdue_level}</span>}
                            {nodeRec.zone && nodeRec.zone !== "unknown" && <span>Zone: {nodeRec.zone}</span>}
                            {nodeRec.type && nodeRec.type !== "unknown" && <span>Type: {nodeRec.type}</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )
              }
            </div>
          </div>
        )}

        {/* ── TAB: MITRE Mapping ───────────────────────────────────── */}
        {activeTab === "mitre" && analysis && (
          <div className="tab-content animate-in">
            <div className="card">
              <div className="card-title"><Shield size={14} /> MITRE ATT&CK for ICS Mapping</div>
              <p className="hint">Identified threat techniques mapped to authorization (Ea) and communication (Ec) edges:</p>
              {(!analysis.mitre_mapping?.technique_summary || analysis.mitre_mapping.technique_summary.length === 0)
                ? <EmptyState icon={CheckCircle} message="No MITRE mappings found." />
                : (
                  <>
                    {/* Tactics breakdown */}
                    {analysis.mitre_mapping.tactic_summary && (
                      <div className="tactic-summary-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 5, marginBottom: 10 }}>
                        {Object.entries(analysis.mitre_mapping.tactic_summary).map(([tactic, count], i) => (
                          <div key={i} style={{ background: "var(--bg-void)", border: "1px solid var(--border-subtle)", borderRadius: 6, padding: "5px 8px", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 9.5 }}>
                            <span style={{ color: "var(--text-secondary)", fontWeight: 500 }}>{tactic}</span>
                            <span className="badge badge-ea" style={{ padding: "1px 5px", fontSize: 8 }}>{count}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Techniques list */}
                    <div className="mitre-techniques-list" style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 300, overflowY: "auto" }}>
                      {analysis.mitre_mapping.technique_summary.map((tech, idx) => (
                        <div key={idx} style={{ background: "var(--bg-void)", border: "1px solid var(--border-subtle)", borderRadius: 9, padding: "8px 10px" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
                            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700, color: "var(--text-primary)" }}>{tech.id}</span>
                            <span className="badge badge-object" style={{ textTransform: "uppercase" }}>{tech.tactic}</span>
                          </div>
                          <div style={{ fontSize: 11, fontWeight: 600, color: "var(--accent-bright)", marginBottom: 4 }}>{tech.name}</div>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 9.5 }}>
                            <span style={{ color: "var(--text-muted)" }}>Occurrences: <strong>{tech.count}</strong></span>
                            <a href={tech.url} target="_blank" rel="noopener noreferrer" style={{ color: "var(--accent)", textDecoration: "none", display: "flex", alignItems: "center", gap: 2 }}>
                              Mitre Spec <ChevronRight size={10} />
                            </a>
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                )
              }
            </div>
          </div>
        )}

        {/* ── TAB: Threat Propagation ─────────────────────────────── */}
        {activeTab === "propagation" && analysis && (
          <div className="tab-content animate-in">
            <div className="card">
              <div className="card-title"><Zap size={14} style={{ color: "var(--text-primary)" }} /> Threat Propagation Simulation</div>
              <p className="hint">Simulate step-by-step infection spread from compromise entry points.</p>

              {/* Select simulation origin */}
              <div style={{ marginBottom: 10 }}>
                <label style={{ display: "block", fontSize: 9.5, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>
                  Infection Origin (Patient Zero):
                </label>
                <select
                  value={activePropNode || ""}
                  onChange={(e) => {
                    const origin = e.target.value;
                    setActivePropNode(origin);
                    setPropDepth(0);
                    setActivePathIndex(-1);
                    clearBlast();
                  }}
                  style={{
                    width: "100%",
                    background: "var(--bg-input)",
                    border: "1px solid var(--border-default)",
                    color: "var(--text-primary)",
                    borderRadius: 8,
                    padding: "6px 10px",
                    fontSize: 12,
                    fontFamily: "'JetBrains Mono', monospace",
                    outline: "none"
                  }}
                >
                  {analysis.threat_propagation && Object.keys(analysis.threat_propagation).map((origin) => (
                    <option key={origin} value={origin}>{origin}</option>
                  ))}
                </select>
              </div>

              {activePropNode && analysis.threat_propagation?.[activePropNode] ? (
                (() => {
                  const sim = analysis.threat_propagation[activePropNode];
                  if (sim.error) {
                    return <p className="hint" style={{ color: "var(--danger)" }}>Simulation error: {sim.error}</p>;
                  }
                  const maxDepth = sim.spread_depth || 0;
                  const currentTimeline = sim.propagation_timeline || [];

                  // Get infected nodes up to selected depth
                  const currentInfected = currentTimeline.filter(item => item.depth <= propDepth);
                  const newInfectedThisStep = currentTimeline.filter(item => item.depth === propDepth);

                  return (
                    <>
                      {/* Simulation stats */}
                      <div className="stat-grid" style={{ marginBottom: 10 }}>
                        <div className="stat-cell" style={{ border: "1px solid var(--border-default)" }}>
                          <span className="stat-val" style={{ color: "#000000" }}>{currentInfected.length}</span>
                          <span className="stat-label">Infected</span>
                        </div>
                        <div className="stat-cell">
                          <span className="stat-val">{maxDepth}</span>
                          <span className="stat-label">Max Hops</span>
                        </div>
                        <div className="stat-cell">
                          <span className="stat-val" style={{ color: "#000000" }}>{sim.critical_nodes_hit?.length || 0}</span>
                          <span className="stat-label">Crown Jewels</span>
                        </div>
                        <div className="stat-cell">
                          <span className="stat-val">{sim.impact_score}</span>
                          <span className="stat-label">Impact Score</span>
                        </div>
                      </div>

                      {/* Stepper slider */}
                      <div style={{ background: "var(--bg-void)", border: "1px solid var(--border-subtle)", borderRadius: 8, padding: 10, marginBottom: 10 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                          <span style={{ fontSize: 10, fontWeight: 700, color: "var(--text-secondary)" }}>Propagation Step (Depth):</span>
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 800, color: "#000000" }}>Step {propDepth} / {maxDepth}</span>
                        </div>
                        <input
                          type="range"
                          min="0"
                          max={maxDepth}
                          value={propDepth}
                          onChange={(e) => setPropDepth(parseInt(e.target.value, 10))}
                          style={{ width: "100%", cursor: "pointer", accentColor: "#000000" }}
                        />
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 8.5, color: "var(--text-muted)", marginTop: 2 }}>
                          <span>Patient Zero</span>
                          <span>Max Propagation</span>
                        </div>
                      </div>

                      {/* Infected list this step */}
                      <div className="infected-step-info">
                        <h4 style={{ fontSize: 10, color: "var(--text-secondary)", fontWeight: 700, marginBottom: 5 }}>
                          {propDepth === 0 ? "Initial Compromise Point:" : `Newly Infected at Step ${propDepth} (${newInfectedThisStep.length}):`}
                        </h4>
                        {newInfectedThisStep.length === 0 ? (
                          <p className="hint">No new nodes infected at this depth.</p>
                        ) : (
                          <ul className="aasg-list" style={{ maxHeight: 150 }}>
                            {newInfectedThisStep.map((item, i) => (
                              <li key={i} className="aasg-vertex-item" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-card-hover)", padding: "5px 8px", borderRadius: 6, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10.5, fontWeight: 600, color: "var(--text-primary)" }}>{item.infected_node}</span>
                                <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
                                  {item.from_node && <span style={{ fontSize: 8, color: "var(--text-muted)" }}>via {item.from_node}</span>}
                                  <span className="badge badge-allowed" style={{ padding: "1px 4px", fontSize: 8 }}>{Math.round(item.probability * 100)}% prob</span>
                                </div>
                              </li>
                            ))}
                          </ul>
                        )}
                      </div>
                    </>
                  );
                })()
              ) : (
                <EmptyState icon={Zap} message="No threat propagation results found." />
              )}
            </div>
          </div>
        )}

        {/* ── TAB: Lateral Movement ────────────────────────────────── */}
        {activeTab === "lateral" && analysis && (
          <div className="tab-content animate-in">
            {/* Stats Summary */}
            <div className="card">
              <div className="card-title"><GitBranch size={14} /> Lateral Movement Summary</div>
              <div className="stat-grid" style={{ marginBottom: 6 }}>
                <div className="stat-cell">
                  <span className="stat-val">{analysis.lateral_movement?.cross_zone_count || 0}</span>
                  <span className="stat-label">Cross Zone</span>
                </div>
                <div className="stat-cell">
                  <span className="stat-val">{analysis.lateral_movement?.privilege_escalation_count || 0}</span>
                  <span className="stat-label">Priv Esc</span>
                </div>
                <div className="stat-cell">
                  <span className="stat-val">{analysis.lateral_movement?.purdue_violation_count || 0}</span>
                  <span className="stat-label">Purdue Viol</span>
                </div>
                <div className="stat-cell">
                  <span className="stat-val">{analysis.lateral_movement?.remote_chain_count || 0}</span>
                  <span className="stat-label">Remote</span>
                </div>
              </div>
            </div>

            {/* High Risk Paths / Chains */}
            <div className="card">
              <div className="card-title"><Activity size={14} /> Reconstructed Movement Chains</div>
              <p className="hint">Pivoting paths from entry points to critical targets:</p>
              {(!analysis.lateral_movement?.high_risk_paths || analysis.lateral_movement.high_risk_paths.length === 0)
                ? <EmptyState icon={CheckCircle} message="No lateral chains detected." />
                : (
                  <div className="paths-list" style={{ maxHeight: 180 }}>
                    {analysis.lateral_movement.high_risk_paths.map((pRec, idx) => (
                      <div
                        key={idx}
                        className={`path-item ${activeLatChainIndex === idx ? "selected" : ""}`}
                        style={{
                          borderColor: activeLatChainIndex === idx ? "#000000" : "var(--border-subtle)",
                          background: activeLatChainIndex === idx ? "var(--bg-card-hover)" : "var(--bg-void)"
                        }}
                        onClick={() => {
                          setActiveLatEventIndex(-1);
                          setActivePathIndex(-1);
                          clearBlast();
                          setActiveLatChainIndex(activeLatChainIndex === idx ? -1 : idx);
                        }}
                      >
                        <div className="path-meta">
                          <span className="path-idx">Chain #{idx + 1}</span>
                          <span className="path-risk" style={{ color: "var(--text-primary)" }}>
                            {pRec.max_severity}
                          </span>
                        </div>
                        <div className="path-details">
                          <span>Pivots: {pRec.movement_count}</span>
                          <span>Hops: {pRec.path?.length - 1}</span>
                        </div>
                        <div className="path-chain">{pRec.path?.join(" → ")}</div>
                      </div>
                    ))}
                  </div>
                )
              }
            </div>

            {/* Individual Pivot Events */}
            <div className="card">
              <div className="card-title"><Lock size={14} /> Specific Pivot Violations ({analysis.lateral_movement?.movement_events?.length || 0})</div>
              {(!analysis.lateral_movement?.movement_events || analysis.lateral_movement.movement_events.length === 0)
                ? <EmptyState icon={CheckCircle} message="No specific pivot events found." />
                : (
                  <div className="pivot-events-list" style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 180, overflowY: "auto" }}>
                    {analysis.lateral_movement.movement_events.map((ev, idx) => {
                      const isSelected = activeLatEventIndex === idx;
                      const sevColor = "#000000";

                      return (
                        <div
                          key={idx}
                          style={{
                            background: isSelected ? "var(--bg-card-hover)" : "var(--bg-void)",
                            border: isSelected ? "1px solid #000000" : "1px solid var(--border-subtle)",
                            borderRadius: 9,
                            padding: "8px 10px",
                            cursor: "pointer",
                            transition: "all 0.15s ease"
                          }}
                          onClick={() => {
                            setActiveLatChainIndex(-1);
                            setActivePathIndex(-1);
                            clearBlast();
                            setActiveLatEventIndex(isSelected ? -1 : idx);
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
                            <span style={{ fontSize: 9.5, fontWeight: 700, padding: "1px 5px", borderRadius: 4, background: "var(--bg-void)", border: "1px solid var(--border-subtle)", color: sevColor }}>
                              {ev.movement_type}
                            </span>
                            <span style={{ fontSize: 8.5, fontWeight: 700, color: sevColor }}>{ev.severity}</span>
                          </div>
                          <div style={{ fontSize: 10.5, color: "var(--text-primary)", fontWeight: 600, fontFamily: "'JetBrains Mono', monospace", marginBottom: 2 }}>
                            {ev.from_node} → {ev.to_node}
                          </div>
                          <p style={{ fontSize: 9.5, color: "var(--text-secondary)", margin: 0, lineHeight: 1.3 }}>{ev.description}</p>
                        </div>
                      );
                    })}
                  </div>
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

            {viewMode === "asset" && (
              <div className="canvas-filters" style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                <input
                  type="text"
                  placeholder="Search assets..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderRadius: "8px",
                    border: "1px solid var(--border-default)",
                    width: "150px",
                    outline: "none",
                    background: "var(--bg-input)",
                    color: "var(--text-primary)",
                  }}
                />
                <select
                  value={zoneFilter}
                  onChange={(e) => setZoneFilter(e.target.value)}
                  style={{
                    padding: "5px 10px",
                    fontSize: "11px",
                    borderRadius: "8px",
                    border: "1px solid var(--border-default)",
                    background: "#ffffff",
                    color: "var(--text-primary)",
                    outline: "none",
                    cursor: "pointer",
                  }}
                >
                  <option value="all">All Zones</option>
                  {(analysis.layout_metadata?.zones_rendered || []).map((zone) => (
                    <option key={zone} value={zone}>
                      {zone.replace(/_/g, " ").toUpperCase()}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div className="canvas-legend">
              <span className="legend-hint">Scroll: Pan · Ctrl+Scroll: Zoom</span>
              <div className="legend-sep" />
              <div className="legend-item"><span className="legend-dot" style={{ background: "#ef4444" }} />Level 0/1</div>
              <div className="legend-item"><span className="legend-dot" style={{ background: "#ea580c" }} />Level 2</div>
              <div className="legend-item"><span className="legend-dot" style={{ background: "#eab308" }} />Level 3</div>
              <div className="legend-item"><span className="legend-dot" style={{ background: "#3b82f6" }} />Level 4/5</div>
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
            style: { stroke: "rgba(0,0,0,0.3)", strokeWidth: 1.2 },
            markerEnd: { type: MarkerType.ArrowClosed, color: "rgba(0,0,0,0.3)", width: 10, height: 10 },
          }}
        >
          <Background variant={BackgroundVariant.Dots} color="#cbd5e1" gap={28} size={1.2} />
          <Panel position="top-left">
            <div className="edge-legend" style={{ background: "#ffffff", border: "1px solid var(--border-default)", borderRadius: 6 }}>
              <span className="lg"><span className="swatch ea" /> Eₐ authorization</span>
              <span className="lg"><span className="swatch ec" /> E_c communication</span>
            </div>
          </Panel>
          <Controls showInteractive={false} />
          <MiniMap
            nodeColor={(n) => typeColors[n.data?.type || n.type] || "#ffffff"}
            maskColor="rgba(255,255,255,0.75)"
            style={{ background: "#ffffff", border: "1px solid var(--border-default)" }}
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