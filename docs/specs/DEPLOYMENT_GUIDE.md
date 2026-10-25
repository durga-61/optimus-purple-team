# DEPLOYMENT GUIDE

## Defender-Only Mode

The application must run without any LLM API key.

Start:

1. backend;
2. frontend;
3. simulator;
4. open Organization Security Portal.

The complete security system must function.

---

## AI Attacker Mode

Configure:

```text
LLM_PROVIDER=openai
OPENAI_API_KEY=
```

or:

```text
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=
```

Enable:

```text
ENABLE_AI_ATTACKER=true
```

Never commit actual API keys.

---

## Required Documentation

Document:

* installation;
* dependencies;
* environment variables;
* backend startup;
* frontend startup;
* simulation;
* testing;
* AI configuration;
* troubleshooting.

---

## Deployment Safety

The attacker interface must not be publicly exposed without appropriate access control.

The attacker is intended to operate against the simulated environment only.
