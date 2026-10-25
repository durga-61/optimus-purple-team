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
