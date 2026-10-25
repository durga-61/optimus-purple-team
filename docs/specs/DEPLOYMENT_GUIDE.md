# DEPLOYMENT GUIDE

## Prerequisites: dataset and environment

1. Install dependencies: `pip install -r requirements.txt`
2. Prepare the real dataset (not vendored in git): `python scripts/fetch_dataset.py`
   - Downloads `Preprocessed.zip` from Zenodo record 15130001, verifies its MD5 against `data/DATASET_MANIFEST.json`, extracts the sensor CSVs and builds the SQLite replay cache.
   - No network access? Start in simulator mode instead: `DATA_SOURCE_MODE=simulator`.
3. Copy `.env.example` to `.env` and set `OPERATOR_TOKEN`, `ATTACK_GATEWAY_TOKEN`, and `ATTACKER_API_KEY`.

`python run.py` validates the configured data source at startup and exits with instructions when the dataset is missing.

---

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
ATTACKER_LLM_PROVIDER=openai
OPENAI_API_KEY=
```

or:

```text
ATTACKER_LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=
```

Leave the API keys empty to use the deterministic (non-LLM) planner.

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
