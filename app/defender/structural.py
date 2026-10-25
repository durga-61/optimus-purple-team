"""Structural analysis engine using NetworkX graph topology.

Models entity and subsystem dependencies to assess whether detected anomalies
span structurally coupled operational components, multi-sensor clusters, or physical cold-room zones.
"""

import logging
from typing import List, Optional, Tuple
import networkx as nx

from app.defender.models import StructuralResult, SemanticResult, MLResult

logger = logging.getLogger("defender.structural")


class StructuralEngine:
    """Evaluates relational graph dependencies between organization entities and cold-storage sensors."""

    def __init__(self):
        self.graph = nx.Graph()
        self._build_topology()

    def _build_topology(self) -> None:
        """Construct the organizational subsystem and cold-storage sensor relational graph."""
        nodes = [
            ("warehouse", {"type": "facility", "label": "Warehouse W01 / Hohenheim"}),
            ("inventory_ledger", {"type": "ledger", "label": "Inventory System"}),
            ("capacity_management", {"type": "ledger", "label": "Capacity Allocations"}),
            ("shipment_gateway", {"type": "logistics", "label": "Inbound/Outbound Gateway"}),
            ("occupancy_sensor", {"type": "sensor", "label": "Physical Occupancy Sensor"}),
            ("environmental_iot", {"type": "sensor", "label": "IoT Temp & Humidity Telemetry"}),
            ("historical_profile", {"type": "baseline", "label": "Historical Operational Envelope"}),
            # Real Cold-Room Multi-Sensor & Physical Zones Topology
            ("ambient_zone", {"type": "zone", "label": "Cold-Storage Ambient Zone"}),
            ("door_entry_zone", {"type": "zone", "label": "Cold-Room Door Entry Zone"}),
            ("cooling_evaporator_zone", {"type": "zone", "label": "Evaporator / Cooling Unit Zone"}),
            ("sensor_cluster_primary", {"type": "cluster", "label": "Fixed Ambient Sensors (S01, S02, S06)"}),
            ("sensor_cluster_door", {"type": "cluster", "label": "Door & Perimeter Sensors (S04, S07)"}),
            ("sensor_cluster_mobile", {"type": "cluster", "label": "Mobile Experimental Sensors (S05, S09)"}),
        ]
        self.graph.add_nodes_from(nodes)

        # Edges represent operational coupling and physical spatial adjacency
        edges = [
            ("warehouse", "inventory_ledger"),
            ("warehouse", "capacity_management"),
            ("warehouse", "shipment_gateway"),
            ("warehouse", "environmental_iot"),
            ("warehouse", "ambient_zone"),
            ("warehouse", "door_entry_zone"),
            ("warehouse", "cooling_evaporator_zone"),
            ("inventory_ledger", "capacity_management"),  # C1 constraint boundary
            ("inventory_ledger", "shipment_gateway"),      # C2 flow boundary
            ("inventory_ledger", "occupancy_sensor"),      # Physical sensor check
            ("environmental_iot", "historical_profile"),   # C3 baseline envelope
            # Physical zone couplings
            ("ambient_zone", "sensor_cluster_primary"),
            ("ambient_zone", "door_entry_zone"),
            ("ambient_zone", "cooling_evaporator_zone"),
            ("door_entry_zone", "sensor_cluster_door"),
            ("cooling_evaporator_zone", "sensor_cluster_primary"),
            ("ambient_zone", "sensor_cluster_mobile"),
            ("environmental_iot", "ambient_zone"),
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
            affected.add("ambient_zone")
            affected.add("sensor_cluster_primary")

        # Map C4 spatial multi-sensor discrepancies
        c4_flagged = any(c.constraint == "C4" and c.status in ("VIOLATED", "WARNING") for c in constraints)
        if c4_flagged:
            affected.add("door_entry_zone")
            affected.add("sensor_cluster_door")
            affected.add("ambient_zone")

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
        has_ledger = any(n in affected for n in ("inventory_ledger", "capacity_management", "shipment_gateway", "occupancy_sensor"))
        has_environmental = any(n in affected for n in ("environmental_iot", "historical_profile", "ambient_zone", "sensor_cluster_primary"))
        has_door_perimeter = any(n in affected for n in ("door_entry_zone", "sensor_cluster_door"))

        if has_ledger and (has_environmental or has_door_perimeter):
            status = "MULTI_SOURCE"
            score = 0.85
            explanation = (
                f"Multi-source structural correlation detected: Anomalies span both operational ledgers "
                f"and physical environmental IoT sensors/zones ({', '.join(affected_nodes)})."
            )
        elif len(correlated_edges) >= 2 or (has_environmental and has_door_perimeter):
            status = "CORRELATED"
            score = 0.50
            explanation = (
                f"CORRELATED STRUCTURAL ANOMALY: Multiple adjacent operational entities or cold-room zones affected "
                f"({', '.join(affected_nodes)})."
            )
        else:
            status = "ISOLATED"
            score = 0.20
            explanation = f"Isolated anomalies detected without widespread structural correlation ({', '.join(affected_nodes)})."

        return StructuralResult(
            structural_score=score,
            status=status,
            affected_nodes=affected_nodes,
            correlated_edges=correlated_edges,
            explanation=explanation,
        )
