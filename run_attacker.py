"""Entry point script for Part 2 AI Attacker Application.

Runs the isolated FastAPI server on port 8001 (by default).
Communicates with Part 1 exclusively via HTTP Attack Gateway.
"""

import argparse
import logging
import sys
import uvicorn

from attacker_app.config import config

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("attacker.runner")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Part 2 AI Attacker Application")
    parser.add_argument("--host", type=str, default=config.HOST, help="Host interface to bind server")
    parser.add_argument("--port", type=int, default=config.PORT, help="Port to bind server (default: 8001)")
    parser.add_argument(
        "--gateway",
        type=str,
        default=config.GATEWAY_BASE_URL,
        help="Part 1 Attack Gateway URL (default: http://127.0.0.1:8000/api/attacker)",
    )
    args = parser.parse_args()

    # Update configuration from CLI arguments if specified
    config.HOST = args.host
    config.PORT = args.port
    config.GATEWAY_BASE_URL = args.gateway.rstrip("/")

    logger.info("=" * 70)
    logger.info("  PART 2: AI ATTACKER / ADVERSARIAL EVALUATION APPLICATION")
    logger.info("=" * 70)
    logger.info(f"Attacker Console UI:   http://{args.host}:{args.port}")
    logger.info(f"Attacker OpenAPI Docs: http://{args.host}:{args.port}/docs")
    logger.info(f"Target Attack Gateway: {config.GATEWAY_BASE_URL}")
    logger.info("Strict Isolation:      NO direct imports or access to Part 1 code/models")
    logger.info("Human-in-the-Loop:     Proposals require human approval before execution")
    logger.info("=" * 70)

    uvicorn.run("attacker_app.main:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
