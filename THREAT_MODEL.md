# THREAT MODEL

## Protected Asset

Integrity of operational and IoT data.

## Potential Attackers

An attacker may compromise or manipulate one or more data sources.

## Attack Types

### Capacity Manipulation

Changes reported capacity/free capacity.

### Inventory Manipulation

Changes inventory records.

### Sensor Spoofing

Changes sensor observations.

### Replay

Reuses previously valid observations.

### Coordinated Manipulation

Changes multiple related values.

### Multi-Source Manipulation

Changes multiple sources consistently.

## Security Goal

Detect suspicious inconsistencies and provide evidence explaining the detection.

## Trust Assumption

The defender may retain some trusted or independent information.

## Known Boundary

If every independent source of evidence is compromised consistently, the system may not be able to determine which state is true.

This is a system limitation.

## AI Attacker Boundary

The AI attacker is intentionally sandboxed.

It can only perform predefined data manipulation operations.

It cannot execute arbitrary commands or access the host system.
