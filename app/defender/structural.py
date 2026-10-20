"""Structural analysis engine using NetworkX graph topology.

Models entity and subsystem dependencies to assess whether detected anomalies
span structurally coupled operational components.
"""

import logging
from typing import List, Optional, Tuple
import networkx as nx

from app.defender.models import StructuralResult, SemanticResult, MLResult

logger = logging.getLogger("defender.structural")


class StructuralEngine:
    """Evaluates relational graph dependencies between organization entities."""

    def __init__(self):
        self.graph = nx.Graph()
        self._build_topology()

    def _build_topology(self) -> None:
        """Construct the organizational subsystem relational graph."""
        nodes = [
            ("warehouse", {"type": "facility", "label": "Warehouse W01"}),
            ("inventory_ledger", {"type": "ledger", "label": "Inventory System"}),
            ("capacity_management", {"type": "ledger", "label": "Capacity Allocations"}),
            ("shipment_gateway", {"type": "logistics", "label": "Inbound/Outbound Gateway"}),
            ("occupancy_sensor", {"type": "sensor", "label": "Physical Occupancy Sensor"}),
            ("environmental_iot", {"type": "sensor", "label": "IoT Temp & Humidity Telemetry"}),
            ("historical_profile", {"type": "baseline", "label": "Historical Operational Envelope"}),
        ]
        self.graph.add_nodes_from(nodes)

        # Edges represent operational and logical coupling
        edges = [
            ("warehouse", "inventory_ledger"),
            ("warehouse", "capacity_management"),
            ("warehouse", "shipment_gateway"),
            ("warehouse", "environmental_iot"),
            ("inventory_ledger", "capacity_management"),  # C1 constraint boundary
            ("inventory_ledger", "shipment_gateway"),      # C2 flow boundary
            ("inventory_ledger", "occupancy_sensor"),      # Physical sensor check
            ("environmental_iot", "historical_profile"),   # C3 baseline envelope
        ]
        self.graph.add_edges_from(edges)

    def analyze(
        self,
        semantic_result: Optional[SemanticResult] = None,
        ml_result: Optional[MLResult] = None,
    ) -> StructuralResult:
        """Evaluate affected organizational entities and compute structural correlation score."""
        affected = set()

        violated_constraints = semantic_result.violated_constraints if semantic_result else []
        constraints = semantic_result.constraints if semantic_result else []

        # Map semantic constraint violations to organizational nodes
        if "C1" in violated_constraints:
            affected.add("inventory_ledger")
            affected.add("capacity_management")
            affected.add("occupancy_sensor")

        if "C2" in violated_constraints:
            affected.add("inventory_ledger")
            affected.add("shipment_gateway")

        # Map C3 and ML environmental anomalies
        c3_flagged = any(c.constraint == "C3" and c.status in ("VIOLATED", "WARNING") for c in constraints)
        ml_anomaly = bool(ml_result and (ml_result.is_anomaly or ml_result.anomaly_score > 0.60))
        if c3_flagged or ml_anomaly:
            affected.add("environmental_iot")
            affected.add("historical_profile")

        affected_nodes = sorted(list(affected))

        if not affected_nodes:
            return StructuralResult(
                structural_score=0.0,
                status="ISOLATED",
                affected_nodes=[],
                correlated_edges=[],
                explanation="No anomalous organizational entities detected in structural graph.",
            )

        # Identify correlated edges among affected nodes
        subgraph = self.graph.subgraph(affected_nodes)
        correlated_edges = [[u, v] for u, v in subgraph.edges()]

        # Compute structural score based on extent of cross-subsystem compromise
        # MULTI_SOURCE occurs when both internal ledger records and external environmental IoT sensors are concurrently affected
        has_ledger = any(n in affected for n in ("inventory_ledger", "capacity_management", "shipment_gateway", "occupancy_sensor"))
        has_sensor = "environmental_iot" in affected

        if has_ledger and has_sensor:
            status = "MULTI_SOURCE"
            structural_score = min(0.90, 0.40 + len(correlated_edges) * 0.15 + len(affected_nodes) * 0.05)
            explanation = (
                f"Multi-source structural correlation: simultaneous anomalies across ledger "
                f"systems and physical environmental sensors ({', '.join(affected_nodes)})."
            )
        elif len(correlated_edges) > 0:
            status = "CORRELATED"
            structural_score = min(0.60, 0.25 + len(correlated_edges) * 0.10)
            explanation = (
                f"Correlated structural anomaly: detected inconsistencies span tightly coupled "
                f"components ({', '.join(affected_nodes)})."
            )
        else:
            status = "ISOLATED"
            structural_score = 0.20
            explanation = f"Isolated anomaly affecting entity: {', '.join(affected_nodes)}."

        return StructuralResult(
            structural_score=round(structural_score, 2),
            status=status,
            affected_nodes=affected_nodes,
            correlated_edges=correlated_edges,
            explanation=explanation,
        )
