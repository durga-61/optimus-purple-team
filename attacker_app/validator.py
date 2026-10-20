"""Local Proposal Validator for Part 2 AI Attacker Application.

Performs local pre-flight checks on candidate attack proposals before
transmission to the Part 1 Attack Gateway.
"""

from typing import Any, Dict, Tuple, Union
from pydantic import ValidationError

from attacker_app.schemas import AttackProposal, ProposalValidationResult

VALID_TARGETS = {
    "capacity_manipulation": ["free_capacity", "capacity"],
    "inventory_manipulation": ["inventory"],
    "sensor_spoofing": ["temperature", "humidity", "environmental_sensors"],
    "replay_attack": ["inventory", "telemetry_stream", "state", "observation"],
    "coordinated_weak": ["multi_metric", "inventory_and_capacity"],
    "multi_source": ["facility", "cross_subsystem", "multi_source"],
}


def validate_proposal(
    candidate: Union[AttackProposal, Dict[str, Any]]
) -> Tuple[bool, ProposalValidationResult, Union[AttackProposal, None]]:
    """Validate a candidate attack proposal against whitelist rules.

    Returns:
        (is_valid, validation_result, parsed_proposal_or_none)
    """
    errors = []
    proposal_obj: Union[AttackProposal, None] = None

    if isinstance(candidate, dict):
        try:
            proposal_obj = AttackProposal(**candidate)
        except ValidationError as e:
            for err in e.errors():
                loc = ".".join(str(p) for p in err.get("loc", []))
                errors.append(f"Schema violation at '{loc}': {err.get('msg')}")
            return False, ProposalValidationResult(valid=False, errors=errors), None
        except Exception as e:
            return False, ProposalValidationResult(valid=False, errors=[str(e)]), None
    elif isinstance(candidate, AttackProposal):
        proposal_obj = candidate
    else:
        return False, ProposalValidationResult(valid=False, errors=["Candidate must be AttackProposal or dict"]), None

    # Verify target matches attack type
    allowed_targets = VALID_TARGETS.get(proposal_obj.attack_type, [])
    if proposal_obj.target not in allowed_targets:
        errors.append(
            f"Invalid target '{proposal_obj.target}' for attack type '{proposal_obj.attack_type}'. "
            f"Allowed targets: {allowed_targets}"
        )

    # Validate value constraints
    if proposal_obj.attack_type == "sensor_spoofing":
        if proposal_obj.value is None and proposal_obj.target != "environmental_sensors":
            errors.append("sensor_spoofing requires a non-null float 'value'.")
        elif proposal_obj.target == "temperature" and proposal_obj.value is not None and not (-50.0 <= proposal_obj.value <= 80.0):
            errors.append(f"Temperature value {proposal_obj.value} outside physical envelope [-50.0, 80.0].")
        elif proposal_obj.target == "humidity" and proposal_obj.value is not None and not (0.0 <= proposal_obj.value <= 100.0):
            errors.append(f"Humidity value {proposal_obj.value} outside physical envelope [0.0, 100.0].")

    if proposal_obj.attack_type in ["capacity_manipulation", "inventory_manipulation"]:
        if proposal_obj.value is not None and proposal_obj.value < 0:
            errors.append(f"Value for {proposal_obj.attack_type} cannot be negative.")

    is_valid = len(errors) == 0
    return is_valid, ProposalValidationResult(valid=is_valid, errors=errors), (proposal_obj if is_valid else None)
