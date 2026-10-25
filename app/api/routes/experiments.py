"""FastAPI Router for Controlled Attack Experiment Engine and Evaluation."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.api.auth import verify_operator_access
from app.experiments.engine import experiment_engine
from app.experiments.models import (
    AggregateMetrics,
    AttackExperimentRequest,
    BaselineRunRequest,
    ExperimentResult,
    ScenarioCatalogItem,
)
from app.experiments.scenarios import SCENARIOS_CATALOG

router = APIRouter(prefix="/experiments", tags=["Controlled Attack Experiments"])


@router.get("/scenarios", response_model=List[ScenarioCatalogItem])
def get_attack_scenarios() -> List[ScenarioCatalogItem]:
    """Retrieve catalog of available authentic-data attack scenarios with schemas and explanations."""
    return [
        ScenarioCatalogItem(
            id=item["id"],
            name=item["name"],
            description=item["description"],
            target_layers=item["target_layers"],
            default_parameters=item["default_parameters"],
            parameter_schema=item["parameter_schema"],
        )
        for item in SCENARIOS_CATALOG.values()
    ]


@router.post(
    "/baseline",
    response_model=ExperimentResult,
    dependencies=[Depends(verify_operator_access)],
)
def run_baseline_evaluation(body: BaselineRunRequest) -> ExperimentResult:
    """Run an authentic recorded dataset observation through Defender without manipulation."""
    try:
        return experiment_engine.run_baseline(step=body.step)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute baseline experiment: {exc}",
        )


@router.post(
    "/attack",
    response_model=ExperimentResult,
    dependencies=[Depends(verify_operator_access)],
)
def run_attack_experiment(body: AttackExperimentRequest) -> ExperimentResult:
    """Inject a controlled attack into an observation copy and evaluate with the Defender pipeline."""
    try:
        return experiment_engine.run_attack_experiment(step=body.step, config=body.configuration)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute attack experiment: {exc}",
        )


@router.get("/history", response_model=List[ExperimentResult])
def get_experiment_history(
    limit: int = Query(default=100, ge=1, le=500),
    attack_type: Optional[str] = Query(default=None),
    outcome: Optional[str] = Query(default=None),
    target_sensor: Optional[str] = Query(default=None),
) -> List[ExperimentResult]:
    """Retrieve history of executed evaluation experiments with multi-attribute filtering."""
    return experiment_engine.get_history(
        limit=limit,
        attack_type=attack_type,
        outcome=outcome,
        target_sensor=target_sensor,
    )


@router.get("/metrics", response_model=AggregateMetrics)
def get_experiment_metrics() -> AggregateMetrics:
    """Retrieve cumulative empirical evaluation metrics (Precision, Recall, F1, FPR, latency)."""
    return experiment_engine.compute_metrics()


@router.get("/history/export")
def export_experiment_history_csv() -> Response:
    """Download RFC 4180 compliant CSV file of all recorded evaluation experiments."""
    csv_data = experiment_engine.export_csv()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=optimus_experiments.csv"},
    )


@router.get("/{experiment_id}", response_model=ExperimentResult)
def get_single_experiment(experiment_id: str) -> ExperimentResult:
    """Retrieve complete evidence, configuration, and observations for a specific experiment."""
    exp = experiment_engine.get_experiment_by_id(experiment_id)
    if not exp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Experiment '{experiment_id}' not found.",
        )
    return exp


@router.get("/{experiment_id}/reproducibility")
def get_reproducibility_package(experiment_id: str) -> Dict[str, Any]:
    """Retrieve self-contained reproducibility audit record with dataset provenance and replay snippet."""
    record = experiment_engine.get_reproducibility_record(experiment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Experiment '{experiment_id}' not found.",
        )
    return record


@router.post("/reset", dependencies=[Depends(verify_operator_access)])
def reset_experiments() -> Dict[str, Any]:
    """Reset experiment history log and baseline state."""
    experiment_engine.reset()
    return {"success": True, "message": "Experiment history successfully reset."}
