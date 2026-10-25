# PROJECT REQUIREMENTS

## Project Name

Organization Information Security Monitoring & AI Attack Simulation Platform

## Primary Goal

Provide an organization with a live system for monitoring operational/IoT data and identifying possible data integrity attacks.

## Part 1 - Defender

Required:

* simulated organization;
* IoT data;
* operational records;
* ML detection;
* semantic integrity checks;
* temporal analysis;
* structural analysis;
* joint security engine;
* alerts;
* event logging;
* REST API;
* live dashboard;
* real-time updates;
* deterministic attacks.

## Part 2 - AI Attacker

Required:

* LLM provider;
* attacker console;
* controlled observation;
* structured attack proposals;
* validation;
* controlled execution;
* defender feedback;
* attack history.

## Security Requirements

The attacker must not have arbitrary system access.

The attacker may only modify explicitly permitted simulated organization values through validated API operations.

The defender must remain functional without the AI attacker.

## User Requirements

The organization user must be able to see:

* current security state;
* operational data;
* backend processing;
* alerts;
* explanations;
* historical events.

The attacker user must be able to see:

* target;
* objective;
* proposal;
* validation;
* execution;
* defender response.

## Reliability

The application must handle errors without crashing.

## Configuration

Sensitive values must use environment variables.

## Maintainability

The existing working architecture should be reused wherever practical.
