import { describe, expect, it } from "vitest";

import type { GraphArtifact } from "../../api/contracts";
import { layoutGraph } from "./layout";

describe("Safety Graph layout", () => {
  it("preserves every backend identity and exact edge endpoint", () => {
    const graph: GraphArtifact = {
      schema_version: 2,
      project_id: "sgproj_test",
      graph_fingerprint: "sha256:test",
      completeness: "COMPLETE",
      diagnostics: [],
      nodes: [
        { node_id: "node-a", kind: "PAYMENT_INGRESS", label: "Webhook", backing_symbol_id: "symbol-a", details: null, provenance: [{ kind: "STATIC", reference: "route", source_location: null, supporting_fingerprint: "sha256:a" }] },
        { node_id: "node-b", kind: "TRUST_GATE", label: "Verify", backing_symbol_id: "symbol-b", details: null, provenance: [{ kind: "STATIC", reference: "call", source_location: null, supporting_fingerprint: "sha256:b" }] },
      ],
      edges: [{ edge_id: "edge-exact", source_node_id: "node-a", target_node_id: "node-b", kind: "CALLS", branch: null, provenance: [{ kind: "STATIC", reference: "edge", source_location: null, supporting_fingerprint: "sha256:e" }] }],
    };
    const result = layoutGraph(graph);
    expect(result.nodes.map((node) => node.id)).toEqual(["node-a", "node-b"]);
    expect(result.edges).toHaveLength(1);
    expect(result.edges[0]).toMatchObject({ id: "edge-exact", source: "node-a", target: "node-b" });
    expect(result.edges[0].data?.record).toBe(graph.edges[0]);
  });
});
