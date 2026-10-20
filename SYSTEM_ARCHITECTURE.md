# SYSTEM ARCHITECTURE

## Overall System

```text
                ORGANIZATION
                     |
       +-------------+-------------+
       |             |             |
     IoT         Inventory     Operations
       |             |             |
       +-------------+-------------+
                     |
                     v
              DATA INGESTION
                     |
                     v
             PREPROCESSING
                     |
          +----------+----------+
          |                     |
          v                     v
         ML              SEMANTIC ENGINE
          |                     |
          |                C1 / C2 / C3
          |                     |
          +----------+----------+
                     |
                     v
              TEMPORAL ENGINE
                     |
                     v
             STRUCTURAL ENGINE
                     |
                     v
             JOINT DECISION
                     |
          +----------+----------+
          |                     |
          v                     v
     ALERT SYSTEM         EVENT SYSTEM
          |                     |
          +----------+----------+
                     |
                     v
          ORGANIZATION PORTAL
```

## AI Attacker

```text
             AI ATTACKER
                  |
                  v
          CONTROLLED SNAPSHOT
                  |
                  v
         ATTACK PROPOSAL
                  |
                  v
             VALIDATOR
                  |
                  v
        CONTROLLED SIMULATION
                  |
                  v
          DEFENDER PIPELINE
                  |
                  v
          SECURITY DECISION
                  |
                  v
         CONTROLLED FEEDBACK
                  |
                  +-----> AI
```

## Separation

The AI attacker is external to the defender security engine.

The attacker cannot directly access defender internals.

## Frontend Principle

The frontend does not calculate security decisions.

It displays backend state.

## Backend Principle

The backend owns:

* analysis;
* security decisions;
* validation;
* alerts;
* events;
* organization state.
