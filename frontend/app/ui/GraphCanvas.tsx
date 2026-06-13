"use client";

import cytoscape from "cytoscape";
import { useEffect, useMemo, useRef } from "react";
import type { GraphNode, RunGraph } from "./types";

type Props = {
  graph: RunGraph;
  onSelectNode: (node: GraphNode) => void;
};

export function GraphCanvas({ graph, onSelectNode }: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const nodesById = useMemo(
    () => new Map(graph.nodes.map((node) => [node.id, node])),
    [graph.nodes]
  );

  useEffect(() => {
    if (!containerRef.current) return;
    const riskyPathNodes = new Set(graph.findings.flatMap((finding) => finding.path));
    const cy = cytoscape({
      container: containerRef.current,
      elements: [
        ...graph.nodes.map((node) => ({
          data: {
            id: node.id,
            label: node.type,
            title: node.label,
            trust: node.trust,
            risky: riskyPathNodes.has(node.id)
          }
        })),
        ...graph.edges.map((edge, index) => ({
          data: {
            id: `edge-${index}`,
            source: edge.source,
            target: edge.target,
            label: edge.label
          }
        }))
      ],
      style: [
        {
          selector: "node",
          style: {
            "background-color": (node) => {
              if (node.data("risky")) return "#cf3f3f";
              if (node.data("trust") === "trusted") return "#23835f";
              if (node.data("trust") === "untrusted") return "#d88922";
              return "#3d6fb6";
            },
            label: "data(label)",
            color: "#111827",
            "font-size": 11,
            "font-weight": 700,
            "text-valign": "bottom",
            "text-margin-y": 8,
            width: 34,
            height: 34,
            "border-width": 2,
            "border-color": "#ffffff"
          }
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#9aa8b6",
            "target-arrow-color": "#9aa8b6",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 9,
            color: "#5b6673",
            "text-rotation": "autorotate"
          }
        }
      ],
      layout: {
        name: "breadthfirst",
        directed: true,
        padding: 36,
        spacingFactor: 1.16
      }
    });

    cy.on("tap", "node", (event) => {
      const node = nodesById.get(event.target.id());
      if (node) onSelectNode(node);
    });

    return () => cy.destroy();
  }, [graph, nodesById, onSelectNode]);

  return <div className="graphCanvas" ref={containerRef} />;
}

