import { useMemo, useState } from "react";
import { Background, Controls, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { useDashboardActions, useDashboardState, useServerActionDisabled } from "../../app/state";
import type { GraphEdgeRecord, GraphNodeRecord } from "../../api/contracts";
import { Button, DefinitionList, Fingerprint, PageHeader, Panel, StateMessage, formatLocation } from "../../components/ui";
import { layoutGraph, type GraphEdgeData, type GraphNodeData } from "./layout";

export function SafetyGraphPage() {
  const state = useDashboardState();
  const actions = useDashboardActions();
  const disabled = useServerActionDisabled();
  const [selection, setSelection] = useState<{ type: "node"; value: GraphNodeRecord } | { type: "edge"; value: GraphEdgeRecord } | null>(null);
  const layout = useMemo(() => (state.graph ? layoutGraph(state.graph) : { nodes: [], edges: [] }), [state.graph]);
  return (
    <div className="page graph-page">
      <PageHeader eyebrow="Static + semantic provenance" title="Payment Safety Graph" actions={<Button variant="primary" disabled={disabled} onClick={() => void actions.loadGraph()}>{state.graph ? "Refresh graph" : "Load graph"}</Button>}>
        StateGuard renders the exact backend node and edge identities. Dagre positions the graph; it does not add, merge, repair, or infer relationships.
      </PageHeader>
      {state.verificationPending && !state.graph ? <StateMessage kind="blocked" title="Graph unavailable during verification">No graph request will be sent while the synchronous server is occupied.</StateMessage> : null}
      {!state.graph && !state.verificationPending ? <StateMessage title="Graph not loaded">Loading the dashboard does not reconstruct project authority. Choose Load graph to inspect current source and render its exact graph.</StateMessage> : null}
      {state.graph ? <>
        <div className="graph-meta">
          <span className={`completeness completeness-${state.graph.completeness.toLowerCase()}`}>{state.graph.completeness}</span>
          <span>{state.graph.nodes.length} nodes</span><span>{state.graph.edges.length} edges</span>
          <span><Fingerprint value={state.graph.graph_fingerprint} /></span>
        </div>
        {state.graph.diagnostics.length ? <div className="diagnostic-banner"><strong>Graph coverage diagnostics</strong>{state.graph.diagnostics.map((item, index) => <span key={`${item.code}-${index}`}>{item.code} · {item.impact}</span>)}</div> : null}
        <div className="graph-layout">
          <div className="graph-canvas" aria-label="Interactive Payment Safety Graph">
            <ReactFlow<Node<GraphNodeData>, Edge<GraphEdgeData>>
              nodes={layout.nodes}
              edges={layout.edges}
              fitView
              minZoom={0.28}
              maxZoom={1.5}
              nodesConnectable={false}
              elementsSelectable
              onNodeClick={(_, node: Node<GraphNodeData>) => setSelection({ type: "node", value: node.data.record })}
              onEdgeClick={(_, edge: Edge<GraphEdgeData>) => setSelection({ type: "edge", value: edge.data!.record })}
            >
              <Background gap={24} color="rgba(144, 162, 193, .16)" />
              <Controls showInteractive={false} />
            </ReactFlow>
          </div>
          <Panel eyebrow="Selection" title={selection ? (selection.type === "node" ? selection.value.label : selection.value.kind.replaceAll("_", " ")) : "Choose an element"} className="graph-detail">
            {!selection ? <p className="muted">Select a node or edge with pointer or keyboard to inspect exact provenance.</p> : selection.type === "node" ? <NodeDetail node={selection.value} /> : <EdgeDetail edge={selection.value} />}
          </Panel>
        </div>
        <Panel eyebrow="Text alternative" title="Graph index">
          <div className="text-graph-grid">
            <div><h3>Nodes</h3><ol className="graph-index">{state.graph.nodes.map((node) => <li key={node.node_id}><button onClick={() => setSelection({ type: "node", value: node })}><span>{node.kind.replaceAll("_", " ")}</span><strong>{node.label}</strong><code>{node.node_id}</code></button></li>)}</ol></div>
            <div><h3>Edges</h3><ol className="graph-index">{state.graph.edges.map((edge) => <li key={edge.edge_id}><button onClick={() => setSelection({ type: "edge", value: edge })}><span>{edge.kind.replaceAll("_", " ")}</span><strong>{edge.source_node_id.slice(0, 12)}… → {edge.target_node_id.slice(0, 12)}…</strong><code>{edge.edge_id}</code></button></li>)}</ol></div>
          </div>
        </Panel>
      </> : null}
    </div>
  );
}

function Provenance({ records }: { records: GraphNodeRecord["provenance"] }) {
  return <div className="provenance-list">{records.map((record, index) => <div key={`${record.kind}-${record.reference}-${index}`}><strong>{record.kind.replaceAll("_", " ")}</strong><span>{record.reference}</span><code>{formatLocation(record.source_location)}</code></div>)}</div>;
}

function NodeDetail({ node }: { node: GraphNodeRecord }) {
  return <><DefinitionList items={[["Node kind", node.kind], ["Node ID", <code>{node.node_id}</code>], ["Backing symbol", <Fingerprint value={node.backing_symbol_id} />]]} /><h3>Provenance</h3><Provenance records={node.provenance} />{node.details ? <details><summary>Bounded node details</summary><pre>{JSON.stringify(node.details, null, 2)}</pre></details> : null}</>;
}

function EdgeDetail({ edge }: { edge: GraphEdgeRecord }) {
  return <><DefinitionList items={[["Edge ID", <code>{edge.edge_id}</code>], ["Source", <code>{edge.source_node_id}</code>], ["Target", <code>{edge.target_node_id}</code>], ["Kind", edge.kind]]} /><h3>Provenance</h3><Provenance records={edge.provenance} />{edge.branch ? <details><summary>Branch evidence</summary><pre>{JSON.stringify(edge.branch, null, 2)}</pre></details> : null}</>;
}
