# TESTING AND VALIDATION

## Defender Tests

Test:

* normal operation;
* ML processing;
* semantic C1;
* semantic C2;
* semantic C3;
* temporal processing;
* structural processing;
* joint decisions;
* alert creation;
* event creation.

## Attack Tests

Test:

* capacity manipulation;
* inventory manipulation;
* sensor spoofing;
* replay;
* coordinated manipulation;
* multi-source manipulation.

## Advanced Research Tests

Verify:

* fusion weights are finite, non-negative, bounded, and sum to 1.0;
* unsafe weight updates are rejected atomically and never partially applied;
* threshold calibration honours the false-positive-rate ceiling;
* adaptive weights are deterministic for a seed and non-degrading on validation;
* invariant discovery uses clean training data and explicit candidate families;
* low-coverage, unstable, non-discriminating, and redundant candidates are rejected;
* activated invariants require operator approval and can be rolled back;
* broken custom invariants cannot crash semantic analysis;
* One-Class SVM and PCA fit on normal data only and calibrate on validation data;
* evasion-frontier generation, aggregation, summaries, and CSV/JSON/PNG exports work;
* dataset split manifests and SHA-256 hashes reproduce across exports;
* artifact checksums cover every exported file except the checksum file itself;
* the full miss → proposal → rejection/approval → activation → rollback lifecycle is audit-chained and tamper-evident.

## API Tests

Test:

* valid requests;
* invalid requests;
* missing fields;
* invalid types;
* unsupported targets;
* invalid values.

## AI Attacker Tests

Verify that the AI attacker cannot:

* execute code;
* execute SQL;
* execute shell commands;
* access files;
* modify source;
* modify models;
* modify security scores;
* bypass validation.

## UI Tests

Verify:

* dashboard reflects backend state;
* alerts appear when generated;
* events appear;
* live data updates;
* pipeline state updates;
* attacker console reflects actual execution.

## End-to-End Test

Run:

Normal
→ Attack
→ Backend processing
→ Detection
→ Alert
→ Dashboard update

Then:

AI proposal
→ Validation
→ Execution
→ Defender processing
→ Security result
→ Attacker feedback
