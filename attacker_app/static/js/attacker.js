/**
 * Part 2 AI Attacker Console Client Logic
 * Strictly interacts with Part 2 backend API (port 8001).
 */

document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements
    const statusDot = document.getElementById("gateway-status-dot");
    const statusText = document.getElementById("gateway-status-text");
    const activePlannerBadge = document.getElementById("active-planner-badge");

    // Telemetry Elements
    const obsTarget = document.getElementById("obs-target");
    const obsInventory = document.getElementById("obs-inventory");
    const obsFreeCapacity = document.getElementById("obs-free-capacity");
    const obsTemperature = document.getElementById("obs-temperature");
    const obsHumidity = document.getElementById("obs-humidity");
    const obsOccupancy = document.getElementById("obs-occupancy");
    const btnRefreshObs = document.getElementById("btn-refresh-obs");

    // Planner Elements
    const plannerOptions = document.querySelectorAll(".toggle-option");
    const objectiveHintInput = document.getElementById("objective-hint");
    const btnGenerateProposal = document.getElementById("btn-generate-proposal");

    // Proposal Elements
    const proposalEmpty = document.getElementById("proposal-empty");
    const proposalDetails = document.getElementById("proposal-details");
    const proposalStatusBadge = document.getElementById("proposal-status-badge");
    const propId = document.getElementById("prop-id");
    const propPlannerLabel = document.getElementById("prop-planner-label");
    const propAttackType = document.getElementById("prop-attack-type");
    const propTarget = document.getElementById("prop-target");
    const propValue = document.getElementById("prop-value");
    const propValidation = document.getElementById("prop-validation");
    const propObjective = document.getElementById("prop-objective");
    const btnExecuteProposal = document.getElementById("btn-execute-proposal");
    const btnDiscardProposal = document.getElementById("btn-discard-proposal");

    // History Elements
    const historyTbody = document.getElementById("history-tbody");
    const btnResetAll = document.getElementById("btn-reset-all");

    let currentPlannerMode = "deterministic";

    // Setup Planner Toggles
    plannerOptions.forEach(opt => {
        opt.addEventListener("click", () => {
            plannerOptions.forEach(o => o.classList.remove("active"));
            opt.classList.add("active");
            const radio = opt.querySelector("input[type=radio]");
            radio.checked = true;
            currentPlannerMode = radio.value;

            if (currentPlannerMode === "deterministic") {
                activePlannerBadge.textContent = "DETERMINISTIC FALLBACK";
                activePlannerBadge.className = "badge badge-warning";
            } else {
                activePlannerBadge.textContent = "LLM PLANNER";
                activePlannerBadge.className = "badge badge-danger";
            }
        });
    });

    // In-memory attacker API key (NOT stored in localStorage for security)
    let inMemoryAttackerKey = null;

    async function attackerFetch(url, options = {}) {
        const headers = { ...(options.headers || {}) };
        if (inMemoryAttackerKey && !headers["Authorization"] && !headers["X-API-Key"]) {
            headers["Authorization"] = `Bearer ${inMemoryAttackerKey}`;
        }

        let res = await fetch(url, {
            credentials: "same-origin",
            headers,
            ...options,
        });

        if (res.status === 401) {
            const entered = window.prompt("Attacker API key required. Please enter your API key for this session:");
            if (entered && entered.trim()) {
                inMemoryAttackerKey = entered.trim();
                try {
                    await fetch("/api/attacker/auth/login", {
                        method: "POST",
                        credentials: "same-origin",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ token: inMemoryAttackerKey }),
                    });
                } catch (e) {
                    console.warn("Attacker cookie login failed:", e);
                }
                headers["Authorization"] = `Bearer ${inMemoryAttackerKey}`;
                res = await fetch(url, {
                    credentials: "same-origin",
                    headers,
                    ...options,
                });
            }
        }
        return res;
    }

    // Check Status & Gateway Connection
    async function checkStatus() {
        try {
            const res = await attackerFetch("/api/attacker/status");
            if (!res.ok) throw new Error("Status check failed");
            const data = await res.json();

            if (data.gateway_connected) {
                statusDot.className = "status-dot dot-online";
                statusText.textContent = "Gateway Connected";
            } else {
                statusDot.className = "status-dot dot-offline";
                statusText.textContent = "Gateway Offline";
            }

            // Sync pending proposal if present
            if (data.has_pending_proposal && data.pending_proposal) {
                displayProposal({
                    proposal_id: data.pending_proposal_id,
                    proposal: data.pending_proposal,
                    validation: data.pending_validation,
                    planner_label: data.pending_planner_label,
                    strategy_rationale: data.pending_strategy_rationale,
                    observed_telemetry: data.pending_observed_telemetry,
                });
            }
        } catch (e) {
            statusDot.className = "status-dot dot-offline";
            statusText.textContent = "Attacker API Offline";
        }
    }

    // Fetch Observation
    async function fetchObservation() {
        try {
            const res = await attackerFetch("/api/attacker/observation");
            if (!res.ok) throw new Error("Could not fetch observation");
            const data = await res.json();

            obsTarget.textContent = data.target;
            obsInventory.textContent = data.inventory.toFixed(1);
            obsFreeCapacity.textContent = data.free_capacity.toFixed(1);
            obsTemperature.textContent = data.temperature.toFixed(1);
            obsHumidity.textContent = data.humidity.toFixed(1);
            obsOccupancy.textContent = data.occupancy.toFixed(1);
        } catch (e) {
            console.error("Observation fetch error:", e);
        }
    }

    // Generate Proposal
    async function generateProposal() {
        btnGenerateProposal.disabled = true;
        btnGenerateProposal.textContent = "Generating...";

        try {
            const payload = {
                planner: currentPlannerMode,
                objective_hint: objectiveHintInput.value.trim() || null,
            };

            const res = await attackerFetch("/api/attacker/propose", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });

            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || "Proposal generation failed");
            }

            const data = await res.json();
            displayProposal(data);
        } catch (e) {
            alert("Failed to generate proposal: " + e.message);
        } finally {
            btnGenerateProposal.disabled = false;
            btnGenerateProposal.textContent = "Generate Attack Proposal";
        }
    }

    // Render Proposal in UI
    function displayProposal(data) {
        proposalEmpty.classList.add("hidden");
        proposalDetails.classList.remove("hidden");

        propId.textContent = data.proposal_id || "PROP-0001";
        propPlannerLabel.textContent = data.planner_label || "DETERMINISTIC FALLBACK";

        // 1. Attack Objective
        const proposal = data.proposal || {};
        propObjective.textContent = proposal.objective || "(No objective provided)";

        // 2. Observed Information
        const obs = data.observed_telemetry || {};
        const obsTargetEl = document.getElementById("prop-obs-target");
        const obsInvEl = document.getElementById("prop-obs-inventory");
        const obsFreeEl = document.getElementById("prop-obs-free");
        const obsTempEl = document.getElementById("prop-obs-temp");
        const obsHumEl = document.getElementById("prop-obs-humidity");
        const obsOccEl = document.getElementById("prop-obs-occ");

        if (obsTargetEl) obsTargetEl.textContent = obs.target || "--";
        if (obsInvEl) obsInvEl.textContent = obs.inventory !== undefined ? obs.inventory + " t" : "--";
        if (obsFreeEl) obsFreeEl.textContent = obs.free_capacity !== undefined ? obs.free_capacity + " t" : "--";
        if (obsTempEl) obsTempEl.textContent = obs.temperature !== undefined ? obs.temperature + " °C" : "--";
        if (obsHumEl) obsHumEl.textContent = obs.humidity !== undefined ? obs.humidity + " %" : "--";
        if (obsOccEl) obsOccEl.textContent = obs.occupancy !== undefined ? obs.occupancy + " %" : "--";

        // 3. AI Proposed Strategy
        const stratEl = document.getElementById("prop-strategy-rationale");
        if (stratEl) {
            stratEl.textContent = data.strategy_rationale || "Heuristic tactical assessment formulated by planner.";
        }

        // 4. Structured Attack Proposal
        propAttackType.textContent = proposal.attack_type || "--";
        propTarget.textContent = proposal.target || "--";
        propValue.textContent = proposal.value !== null && proposal.value !== undefined ? proposal.value : "(none/default)";

        const valErrorsEl = document.getElementById("prop-validation-errors");
        const isValid = data.validation && data.validation.valid && data.proposal !== null;
        if (isValid) {
            propValidation.innerHTML = '<span class="badge badge-success">VALIDATED (Whitelisted)</span>';
            btnExecuteProposal.disabled = false;
            proposalStatusBadge.textContent = "READY FOR HUMAN REVIEW";
            proposalStatusBadge.className = "badge badge-warning";
            if (valErrorsEl) valErrorsEl.classList.add("hidden");
        } else {
            const errs = data.validation && data.validation.errors && data.validation.errors.length > 0 
                ? data.validation.errors.join("; ") 
                : "Proposal parsing failed or unsupported attack vector.";
            propValidation.innerHTML = '<span class="badge badge-danger">REJECTED / INVALID</span>';
            btnExecuteProposal.disabled = true;
            proposalStatusBadge.textContent = "REJECTED (EXECUTION BLOCKED)";
            proposalStatusBadge.className = "badge badge-danger";
            if (valErrorsEl) {
                valErrorsEl.textContent = "Validation Errors: " + errs;
                valErrorsEl.classList.remove("hidden");
            }
        }
    }

    // Execute Proposal (Human-in-the-Loop)
    async function executeProposal() {
        btnExecuteProposal.disabled = true;
        btnExecuteProposal.textContent = "Transmitting to Gateway...";

        try {
            const currentPropId = propId.textContent.trim();
            const res = await attackerFetch("/api/attacker/execute", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    proposal_id: currentPropId,
                    approved: true,
                }),
            });

            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || "Execution failed");
            }

            const feedback = await res.json();
            const classMsg = feedback.classification ? `Classification: ${feedback.classification}` : "Classification: SHIELDED";
            alert(`Attack executed via Attack Gateway!\nID: ${feedback.attack_id}\nDetection: ${feedback.detection}\n${classMsg}`);

            // Clear proposal view
            proposalEmpty.classList.remove("hidden");
            proposalDetails.classList.add("hidden");
            proposalStatusBadge.textContent = "NO ACTIVE PROPOSAL";
            proposalStatusBadge.className = "badge badge-neutral";

            // Refresh observation and history
            await fetchObservation();
            await fetchHistory();
        } catch (e) {
            alert("Attack Execution Error: " + e.message);
        } finally {
            btnExecuteProposal.disabled = false;
            btnExecuteProposal.textContent = "Approve & Execute Attack";
        }
    }

    // Discard Proposal
    async function discardProposal() {
        try {
            await attackerFetch("/api/attacker/discard", { method: "POST" });
            proposalEmpty.classList.remove("hidden");
            proposalDetails.classList.add("hidden");
            proposalStatusBadge.textContent = "NO ACTIVE PROPOSAL";
            proposalStatusBadge.className = "badge badge-neutral";
        } catch (e) {
            console.error("Discard failed:", e);
        }
    }

    // Fetch History & Experiment Records
    async function fetchHistory() {
        try {
            const res = await attackerFetch("/api/attacker/experiments");
            if (!res.ok) return;
            const items = await res.json();

            if (items.length === 0) {
                historyTbody.innerHTML = `
                    <tr class="empty-row">
                        <td colspan="8">No experiments executed in this session.</td>
                    </tr>
                `;
                return;
            }

            let html = "";
            items.forEach(exp => {
                const expId = exp.experiment_id || "--";
                const atkId = exp.attack_id || "--";
                const atkType = exp.attack_type || "--";
                const target = exp.target || "--";
                const execution = exp.execution_status || "accepted";
                const detection = exp.detection_status || "--";
                const classification = exp.classification || "SHIELDED";
                const classBadge = exp.classification
                    ? `<span class="badge badge-outline">${exp.classification}</span>`
                    : `<span class="badge badge-neutral" style="opacity: 0.65;">SHIELDED</span>`;
                const delayStr = exp.detection_delay_ms !== undefined && exp.detection_delay_ms !== null
                    ? `${exp.detection_delay_ms} ms`
                    : "--";

                let detectionBadge = `<span class="badge badge-neutral">${detection}</span>`;
                if (detection === "DETECTED") {
                    detectionBadge = `<span class="badge badge-danger">DETECTED</span>`;
                } else if (detection === "UNNOTICED") {
                    detectionBadge = `<span class="badge badge-success">EVADED</span>`;
                }

                html += `
                    <tr>
                        <td><strong>${expId}</strong></td>
                        <td>${atkId}</td>
                        <td class="code-font">${atkType}</td>
                        <td>${target}</td>
                        <td>${execution}</td>
                        <td>${detectionBadge}</td>
                        <td>${classBadge}</td>
                        <td>${delayStr}</td>
                    </tr>
                `;
            });

            historyTbody.innerHTML = html;
        } catch (e) {
            console.error("Experiment records fetch error:", e);
        }
    }

    // Reset All
    async function resetAll() {
        if (!confirm("Reset Part 1 simulator baseline and clear all attacker history?")) {
            return;
        }

        try {
            const res = await attackerFetch("/api/attacker/reset", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scope: "all" }),
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.detail || "Reset failed");
            }
            alert("Simulation baseline and attacker state successfully reset.");
            proposalEmpty.classList.remove("hidden");
            proposalDetails.classList.add("hidden");
            proposalStatusBadge.textContent = "NO ACTIVE PROPOSAL";
            proposalStatusBadge.className = "badge badge-neutral";
            await fetchObservation();
            await fetchHistory();
            await checkStatus();
        } catch (e) {
            alert("Reset Error: " + e.message);
        }
    }

    // Event Listeners
    btnRefreshObs.addEventListener("click", fetchObservation);
    btnGenerateProposal.addEventListener("click", generateProposal);
    btnExecuteProposal.addEventListener("click", executeProposal);
    btnDiscardProposal.addEventListener("click", discardProposal);
    btnResetAll.addEventListener("click", resetAll);

    // Initial Load & Polling
    checkStatus();
    fetchObservation();
    fetchHistory();
    setInterval(checkStatus, 3000);
    setInterval(fetchObservation, 4000);
});
