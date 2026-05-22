import React, { useCallback, useState } from "react";
import { createRoot } from "react-dom/client";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  addEdge,
  useNodesState,
  useEdgesState,
  MarkerType
} from "reactflow";
import "reactflow/dist/style.css";
import axios from "axios";
import dagre from "dagre";
import { Upload, FileText, Network } from "lucide-react";
import "./style.css";

const API_URL = "http://127.0.0.1:8000";

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

function layoutGraph(nodes, edges) {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "LR", nodesep: 80, ranksep: 120 });

  nodes.forEach((node) => {
    g.setNode(node.id, { width: 180, height: 70 });
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
        y: pos.y - 35
      }
    };
  });
}

function convertToReactFlow(graph) {
  const rawNodes = (graph.nodes || []).map((n, index) => ({
    id: String(n.id || `node-${index + 1}`),
    data: {
      label: `${n.label || n.name || "Component"}\n${n.type || "component"}`
    },
    position: { x: 0, y: 0 },
    style: {
      background: typeColors[n.type] || "#ffffff",
      border: "1px solid #334155",
      borderRadius: 14,
      padding: 12,
      width: 180,
      fontSize: 13,
      whiteSpace: "pre-line",
      textAlign: "center"
    }
  }));

  const nodeIds = new Set(rawNodes.map((n) => n.id));

  const rawEdges = (graph.edges || [])
    .filter((e) => nodeIds.has(String(e.source)) && nodeIds.has(String(e.target)))
    .map((e, index) => ({
      id: String(e.id || `edge-${index + 1}`),
      source: String(e.source),
      target: String(e.target),
      label: e.label || e.protocol || "",
      animated: false,
      markerEnd: { type: MarkerType.ArrowClosed },
      style: { strokeWidth: 2 }
    }));

  return {
    nodes: layoutGraph(rawNodes, rawEdges),
    edges: rawEdges
  };
}

function App() {
  const [text, setText] = useState(
    "Internet connects to Firewall. Firewall connects to Web Server. Web Server connects to Database. Admin connects to VPN. VPN connects to Web Server."
  );

  const [file, setFile] = useState(null);
  const [jsonOutput, setJsonOutput] = useState({});
  const [message, setMessage] = useState("Upload a file or generate from text.");

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  const onConnect = useCallback(
    (params) =>
      setEdges((eds) =>
        addEdge(
          {
            ...params,
            markerEnd: { type: MarkerType.ArrowClosed }
          },
          eds
        )
      ),
    [setEdges]
  );

  const applyGraph = (graph) => {
    const converted = convertToReactFlow(graph);

    setNodes(converted.nodes);
    setEdges(converted.edges);
    setJsonOutput(graph);

    setMessage(
      graph.error ||
        graph.warning ||
        `Diagram generated successfully. Nodes: ${converted.nodes.length}, Edges: ${converted.edges.length}`
    );
  };

  const generateFromText = async () => {
    try {
      setMessage("Generating from text...");

      const res = await axios.post(
        `${API_URL}/generate-from-text`,
        { text },
        {
          headers: {
            "Content-Type": "application/json"
          }
        }
      );

      applyGraph(res.data);
    } catch (err) {
      console.error(err);
      setMessage(err.message || "Backend error");
    }
  };

  const generateFromFile = async () => {
    if (!file) {
      setMessage("Please select a file first.");
      return;
    }

    try {
      setMessage("Uploading and processing file...");

      const formData = new FormData();
      formData.append("file", file);

      const res = await axios.post(`${API_URL}/upload`, formData);

      applyGraph(res.data);
    } catch (err) {
      console.error(err);
      setMessage(err.message || "File processing failed");
    }
  };

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(jsonOutput, null, 2)], {
      type: "application/json"
    });

    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "architecture-graph.json";
    a.click();
  };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <Network size={28} />
          <div>
            <h1>Architecture Diagram Generator</h1>
            <p>Image / PDF / Table / Text → JSON → Editable Diagram</p>
          </div>
        </div>

        <section className="card">
          <h2>
            <FileText size={18} /> Text Input
          </h2>

          <textarea value={text} onChange={(e) => setText(e.target.value)} />

          <button onClick={generateFromText}>Generate from Text</button>
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

          <button onClick={generateFromFile}>Generate from File</button>

          <p className="hint">Supports PNG, JPG, PDF, CSV, Excel, TXT</p>
        </section>

        <section className="card">
          <h2>Status</h2>
          <p>{message}</p>
          <button onClick={downloadJson}>Download JSON</button>
        </section>

        <section className="card jsonBox">
          <h2>Graph JSON</h2>
          <pre>{JSON.stringify(jsonOutput, null, 2)}</pre>
        </section>
      </aside>

      <main className="canvas">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          fitView
        >
          <Background />
          <Controls />
          <MiniMap />
        </ReactFlow>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);