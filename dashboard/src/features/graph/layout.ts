import Dagre from "@dagrejs/dagre";
import { MarkerType, type Edge, type Node } from "@xyflow/react";

import type { GraphArtifact, GraphEdgeRecord, GraphNodeRecord } from "../../api/contracts";

export interface GraphNodeData extends Record<string, unknown> { record: GraphNodeRecord; label: string }
export interface GraphEdgeData extends Record<string, unknown> { record: GraphEdgeRecord }

export function layoutGraph(graph: GraphArtifact): { nodes: Node<GraphNodeData>[]; edges: Edge<GraphEdgeData>[] } {
  const layout = new Dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));
  layout.setGraph({ rankdir: "LR", ranksep: 110, nodesep: 46, marginx: 38, marginy: 38 });
  for (const node of graph.nodes) layout.setNode(node.node_id, { width: 230, height: 84 });
  for (const edge of graph.edges) layout.setEdge(edge.source_node_id, edge.target_node_id);
  Dagre.layout(layout);
  return {
    nodes: graph.nodes.map((record) => {
      const position = layout.node(record.node_id) as { x: number; y: number };
      return {
        id: record.node_id,
        data: { record, label: record.label },
        position: { x: position.x - 115, y: position.y - 42 },
        className: `graph-node node-${record.kind.toLowerCase().replaceAll("_", "-")}`,
        ariaLabel: `${record.kind.replaceAll("_", " ")}: ${record.label}`,
      };
    }),
    edges: graph.edges.map((record) => ({
      id: record.edge_id,
      source: record.source_node_id,
      target: record.target_node_id,
      label: record.kind.replaceAll("_", " "),
      data: { record },
      type: "smoothstep",
      markerEnd: { type: MarkerType.ArrowClosed },
      className: "graph-edge",
    })),
  };
}
