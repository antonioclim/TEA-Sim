#!/usr/bin/env python3
"""TEA-Sim reproducibility script.

This script generates deterministic simulation outputs for a standards-compatible
TrustEvidence interface model. The model compares central audit, hash-log and
ledger-like evidence-storage backends under declared parameters. It is not a
clinical implementation, FHIR server, blockchain deployment, cryptographic
runtime benchmark or FHIR conformance test.
"""
from __future__ import annotations

from pathlib import Path
import argparse
import math
import struct
import zlib
from typing import Dict, Tuple

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

ARCHITECTURES = ["A1 Central audit", "A2 Hash log", "A3 Ledger-like"]

LJI_LOWER_THRESHOLD = -0.05
LJI_UPPER_THRESHOLD = 0.10

THREAT_ROWS = [
    ["Payload modified after anchoring", "High if commitment exists", "High", "High", "All architectures can detect payload modification if commitments are preserved; this is design-based detectability, not a penetration-test result."],
    ["Ordinary audit-row deletion", "Medium", "High", "Very high", "Hash continuity and replicated evidence improve deletion detection."],
    ["Malicious central-administrator deletion", "Low", "Medium-high", "High", "This is the main scenario in which a ledger-like evidence backend has a defensible advantage."],
    ["Access after consent revocation", "Medium-high", "High", "High", "All architectures require correct consent-state modelling; replicated evidence improves independent verifiability."],
    ["Policy-version mismatch", "Medium-high", "High", "High", "Hash-linked and replicated evidence better preserve temporal policy evidence."],
    ["Interorganisational dispute", "Low-medium", "Medium", "High", "A ledger-like backend is most defensible when no mutually trusted audit operator exists."],
    ["Metadata exposure risk", "Low-medium", "Medium", "High", "The privacy cost of replicated evidence must be mitigated by minimisation, pseudonymisation and retention control."],
]


def load_params(data_dir: Path) -> Tuple[pd.DataFrame, Dict[str, float | str]]:
    params_df = pd.read_csv(data_dir / "parameter_register.csv")
    params: Dict[str, float | str] = {}
    for k, v in zip(params_df["parameter"], params_df["value"]):
        try:
            params[k] = float(v)
        except Exception:
            params[k] = v
    return params_df, params


def percentile_interval(values, lower=2.5, upper=97.5) -> Tuple[int, int]:
    return int(np.floor(np.percentile(values, lower))), int(np.ceil(np.percentile(values, upper)))


def round_int_half_away_from_zero(value: float) -> int:
    if value >= 0:
        return int(math.floor(value + 0.5))
    return int(math.ceil(value - 0.5))


def simulate_event_counts(scenario, params, rng) -> dict:
    patients = int(params["patients_per_scenario"])
    days = int(params["simulation_horizon_days"])
    obs_per_day = int(params["aggregated_observations_per_patient_day"])
    access_rate = float(scenario["access_rate_per_patient_day"])
    rev_prob = float(scenario["revocation_probability_over_horizon"])

    daily_integrity_anchors = patients * days
    daily_provenance_assertions = patients * days
    consent_grants = patients
    revocations = rng.binomial(n=patients, p=rev_prob)
    access_events = rng.poisson(lam=patients * days * access_rate)
    total_evidence_objects = daily_integrity_anchors + daily_provenance_assertions + consent_grants + revocations + access_events
    conceptual_observations = patients * days * obs_per_day
    return {
        "daily_integrity_anchors": int(daily_integrity_anchors),
        "daily_provenance_assertions": int(daily_provenance_assertions),
        "consent_grants": int(consent_grants),
        "revocations": int(revocations),
        "access_events": int(access_events),
        "evidence_objects": int(total_evidence_objects),
        "conceptual_observations": int(conceptual_observations),
    }


def expected_event_counts(patients: float, days: float, access_rate: float, rev_prob: float, obs_per_day: float) -> dict:
    daily_integrity_anchors = patients * days
    daily_provenance_assertions = patients * days
    consent_grants = patients
    revocations = patients * rev_prob
    access_events = patients * days * access_rate
    total_evidence_objects = daily_integrity_anchors + daily_provenance_assertions + consent_grants + revocations + access_events
    conceptual_observations = patients * days * obs_per_day
    return {
        "daily_integrity_anchors": daily_integrity_anchors,
        "daily_provenance_assertions": daily_provenance_assertions,
        "consent_grants": consent_grants,
        "revocations": revocations,
        "access_events": access_events,
        "evidence_objects": total_evidence_objects,
        "conceptual_observations": conceptual_observations,
    }


def evidence_bytes(architecture: str, profile: str, params: dict) -> float:
    if profile == "classical":
        if architecture == "A1 Central audit":
            return float(params["trust_evidence_a1_classical_bytes"])
        if architecture == "A2 Hash log":
            return float(params["trust_evidence_a2_classical_bytes"])
        return float(params["trust_evidence_a3_classical_bytes_per_org"])
    if profile == "mldsa44":
        if architecture == "A1 Central audit":
            return float(params["trust_evidence_a1_mldsa44_bytes"])
        if architecture == "A2 Hash log":
            return float(params["trust_evidence_a2_mldsa44_bytes"])
        return float(params["trust_evidence_a3_mldsa44_bytes_per_org"])
    raise ValueError(f"Unknown signature profile: {profile}")


def storage_mb(evidence_objects: float, architecture: str, orgs: float, profile: str, params: dict) -> float:
    multiplier = orgs if architecture == "A3 Ledger-like" else 1.0
    return evidence_objects * evidence_bytes(architecture, profile, params) * multiplier / 1_000_000


def write_cost_units(evidence_objects: float, architecture: str, orgs: float, params: dict) -> float:
    if architecture == "A1 Central audit":
        return evidence_objects * float(params["write_cost_factor_a1"])
    if architecture == "A2 Hash log":
        return evidence_objects * float(params["write_cost_factor_a2"])
    return evidence_objects * orgs * float(params["write_cost_factor_a3_per_org"])


def verification_units(access_events: float, architecture: str, params: dict) -> float:
    if architecture == "A1 Central audit":
        return access_events * float(params["verification_factor_a1"])
    if architecture == "A2 Hash log":
        return access_events * float(params["verification_factor_a2"])
    return access_events * float(params["verification_factor_a3"])


def privacy_score(dispute_risk: float, architecture: str) -> float:
    # This is a metadata-exposure proxy only. It is not a legal compliance score.
    if architecture == "A1 Central audit":
        return min(0.25 + 0.25 * dispute_risk + 0.015, 1.0)
    if architecture == "A2 Hash log":
        return min(0.40 + 0.25 * dispute_risk + 0.015, 1.0)
    return min(0.60 + 0.25 * dispute_risk + 0.015, 1.0)


def lji(dispute_risk: float, orgs: int, revocation_probability: float, signature_profile: str) -> Tuple[float, float, float]:
    org_norm = min((orgs - 1) / 4.0, 1.0)
    rev_norm = min(revocation_probability / 0.08, 1.0)
    signature_penalty = 0.17 if signature_profile == "mldsa44" else 0.0
    benefit = 0.45 * dispute_risk + 0.30 * org_norm + 0.25 * rev_norm
    cost = 0.28 + 0.22 * org_norm + 0.18 * rev_norm + signature_penalty
    return benefit, cost, benefit - cost


def preferred_architecture(lji_value: float) -> str:
    if lji_value < LJI_LOWER_THRESHOLD:
        return "A1/A2 preferred; A3 weakly justified or disproportionate."
    if lji_value < LJI_UPPER_THRESHOLD:
        return "Borderline; A2 usually proportionate; A3 requires explicit independent-audit need."
    return "A3 may be justified under stated assumptions."


def strip_png_text_chunks(path: Path) -> None:
    """Remove non-critical textual/time chunks from a PNG while preserving pixels."""
    data = path.read_bytes()
    signature = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(signature):
        return
    offset = len(signature)
    kept = [signature]
    removable = {b"tEXt", b"zTXt", b"iTXt", b"tIME"}
    while offset < len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        chunk_data = data[offset + 8:offset + 8 + length]
        if chunk_type not in removable:
            new_crc = struct.pack(">I", zlib.crc32(chunk_type + chunk_data) & 0xffffffff)
            kept.append(struct.pack(">I", length) + chunk_type + chunk_data + new_crc)
        offset += 12 + length
        if chunk_type == b"IEND":
            break
    path.write_bytes(b"".join(kept))


def save_figure(fig, path: Path, dpi=300) -> None:
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)
    strip_png_text_chunks(path)


def generate_sensitivity_table(params: dict, scenarios: pd.DataFrame) -> pd.DataFrame:
    base = scenarios.loc[scenarios["scenario_id"] == "S2"].iloc[0]
    patients = float(params["patients_per_scenario"])
    days = float(params["simulation_horizon_days"])
    obs_per_day = float(params["aggregated_observations_per_patient_day"])
    access_rate = float(base["access_rate_per_patient_day"])
    rev_prob = float(base["revocation_probability_over_horizon"])
    orgs = float(base["organisations"])
    arch = "A3 Ledger-like"

    def metrics(patients_=patients, days_=days, access_rate_=access_rate, rev_prob_=rev_prob, orgs_=orgs, profile_="classical"):
        counts = expected_event_counts(patients_, days_, access_rate_, rev_prob_, obs_per_day)
        return {
            "evidence_objects": counts["evidence_objects"],
            "storage_mb": storage_mb(counts["evidence_objects"], arch, orgs_, profile_, params),
            "write_cost_units": write_cost_units(counts["evidence_objects"], arch, orgs_, params),
            "verification_units": verification_units(counts["access_events"], arch, params),
        }

    baseline = metrics()
    perturbations = [
        ("Signature profile", "Classical to ML-DSA-44-sized evidence", metrics(profile_="mldsa44")),
        ("Patient count", "-50%", metrics(patients_=patients * 0.5)),
        ("Patient count", "+50%", metrics(patients_=patients * 1.5)),
        ("Simulation horizon", "-50%", metrics(days_=days * 0.5)),
        ("Simulation horizon", "+50%", metrics(days_=days * 1.5)),
        ("Organisational multiplicity", "3 organisations to 2", metrics(orgs_=2)),
        ("Organisational multiplicity", "3 organisations to 4", metrics(orgs_=4)),
        ("Access rate", "-50%", metrics(access_rate_=access_rate * 0.5)),
        ("Access rate", "+50%", metrics(access_rate_=access_rate * 1.5)),
        ("Revocation probability", "-50%", metrics(rev_prob_=rev_prob * 0.5)),
        ("Revocation probability", "+50%", metrics(rev_prob_=rev_prob * 1.5)),
    ]
    rows = []
    for driver, perturbation, changed in perturbations:
        rows.append({
            "baseline_scenario": "S2",
            "baseline_architecture": arch,
            "driver": driver,
            "perturbation": perturbation,
            "delta_storage_mb": round(changed["storage_mb"] - baseline["storage_mb"], 1),
            "delta_write_cost_units": round_int_half_away_from_zero(changed["write_cost_units"] - baseline["write_cost_units"]),
            "delta_verification_units": round_int_half_away_from_zero(changed["verification_units"] - baseline["verification_units"]),
        })
    return pd.DataFrame(rows)


def make_figures(summary_df: pd.DataFrame, lji_df: pd.DataFrame, out_figs: Path) -> None:
    for metric, fname, ylabel in [
        ("storage_mb", "figure_storage_mb.png", "Storage MB"),
        ("verification_units", "figure_verification_units.png", "Normalised verification units"),
        ("privacy_score", "figure_privacy_score.png", "Metadata-exposure proxy"),
        ("write_cost_units", "figure_write_cost_units.png", "Normalised write-cost units"),
    ]:
        fig, ax = plt.subplots(figsize=(10, 5.5))
        pivot = summary_df.pivot(index="scenario_id", columns="architecture", values=metric)
        pivot.plot(kind="bar", ax=ax)
        ax.set_ylabel(ylabel)
        ax.set_xlabel("Scenario")
        ax.set_title(f"TEA-Sim {ylabel} by scenario and architecture")
        ax.tick_params(axis="x", rotation=0)
        save_figure(fig, out_figs / fname)

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(lji_df["scenario_id"], lji_df["LJI"])
    ax.axvline(LJI_LOWER_THRESHOLD, linestyle="--")
    ax.axvline(LJI_UPPER_THRESHOLD, linestyle="--")
    ax.set_xlabel("Ledger Justification Index")
    ax.set_title("Scenario-based Ledger Justification Index")
    save_figure(fig, out_figs / "figure_lji.png")

    # Composite Figure 2 used in the manuscript.
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.5))
    storage_pivot = summary_df.pivot(index="scenario_id", columns="architecture", values="storage_mb")
    storage_pivot.plot(kind="bar", ax=axes[0])
    axes[0].set_ylabel("Storage MB")
    axes[0].set_xlabel("Scenario")
    axes[0].set_title("A. Modelled storage overhead")
    axes[0].tick_params(axis="x", rotation=0)
    axes[1].barh(lji_df["scenario_id"], lji_df["LJI"])
    axes[1].axvline(LJI_LOWER_THRESHOLD, linestyle="--")
    axes[1].axvline(LJI_UPPER_THRESHOLD, linestyle="--")
    axes[1].set_xlabel("Ledger Justification Index")
    axes[1].set_title("B. Ledger-justification heuristic")
    fig.suptitle("Storage burden and conditional ledger justification")
    save_figure(fig, out_figs / "figure_2_storage_lji_composite.png")

    fig, ax = plt.subplots(figsize=(10, 5.8))
    ax.axis("off")
    boxes = [
        (0.05, 0.70, "Mobile/wearable\ndata source"),
        (0.25, 0.70, "FHIR semantic\nboundary"),
        (0.45, 0.70, "Consent/policy\nstate model"),
        (0.65, 0.70, "TrustEvidence\ninterface"),
        (0.85, 0.70, "Verifier /\nauditor"),
        (0.25, 0.32, "Off-chain payload\nrepository"),
        (0.49, 0.32, "A1 Central\naudit log"),
        (0.66, 0.32, "A2 Append-only\nhash log"),
        (0.84, 0.32, "A3 Ledger-like\nevidence backend"),
    ]
    for x, y, text in boxes:
        ax.text(x, y, text, ha="center", va="center", bbox=dict(boxstyle="round,pad=0.45", fc="white", ec="black"))
    arrows = [
        ((0.12, 0.70), (0.19, 0.70)), ((0.32, 0.70), (0.39, 0.70)),
        ((0.52, 0.70), (0.59, 0.70)), ((0.72, 0.70), (0.78, 0.70)),
        ((0.25, 0.64), (0.25, 0.42)), ((0.65, 0.64), (0.49, 0.42)),
        ((0.65, 0.64), (0.66, 0.42)), ((0.65, 0.64), (0.84, 0.42)),
        ((0.85, 0.64), (0.84, 0.42)),
    ]
    for start, end in arrows:
        ax.annotate("", xy=end, xytext=start, arrowprops=dict(arrowstyle="->", lw=1.2))
    ax.text(0.5, 0.08, "Clinical payloads remain off-chain; compact trust evidence is routed to alternative evidence-storage backends.", ha="center")
    save_figure(fig, out_figs / "figure_teasim_architecture.png")


def run_simulation(root: Path):
    data_dir = root / "data"
    out_tables = root / "outputs" / "tables"
    out_figs = root / "outputs" / "figures"
    out_tables.mkdir(parents=True, exist_ok=True)
    out_figs.mkdir(parents=True, exist_ok=True)

    params_df, params = load_params(data_dir)
    scenarios = pd.read_csv(data_dir / "scenario_matrix.csv")
    seed = int(params["random_seed"])
    reps = int(params["monte_carlo_replications"])
    payload_mb = float(params["payload_reference_mb"])
    rng = np.random.default_rng(seed)

    all_rep_rows, summary_rows, lji_rows = [], [], []
    for _, s in scenarios.iterrows():
        orgs = int(s["organisations"])
        dispute = float(s["dispute_risk"])
        revp = float(s["revocation_probability_over_horizon"])
        profile = str(s["signature_profile"])
        rep_counts, rep_access = [], []
        for r in range(1, reps + 1):
            counts = simulate_event_counts(s, params, rng)
            counts["replication"] = r
            counts["scenario_id"] = s["scenario_id"]
            counts["scenario_label"] = s["scenario_label"]
            all_rep_rows.append(counts)
            rep_counts.append(counts["evidence_objects"])
            rep_access.append(counts["access_events"])
        ev_mean = int(round(np.mean(rep_counts)))
        ev_low, ev_high = percentile_interval(rep_counts)
        access_mean = float(np.mean(rep_access))
        for arch in ARCHITECTURES:
            mb = storage_mb(ev_mean, arch, orgs, profile, params)
            wc = write_cost_units(ev_mean, arch, orgs, params)
            vu = verification_units(access_mean, arch, params)
            ps = privacy_score(dispute, arch)
            summary_rows.append({
                "scenario_id": s["scenario_id"],
                "scenario": s["scenario_label"],
                "architecture": arch,
                "signature_profile": profile,
                "evidence_objects_mean": ev_mean,
                "evidence_objects_interval_95": f"[{ev_low}-{ev_high}]",
                "storage_mb": round(mb, 1),
                "evidence_payload_percent": round(mb / payload_mb * 100.0, 2),
                "write_cost_units": round_int_half_away_from_zero(wc),
                "verification_units": round_int_half_away_from_zero(vu),
                "privacy_score": round(ps, 2),
            })
        benefit, cost, index = lji(dispute, orgs, revp, profile)
        lji_rows.append({
            "scenario_id": s["scenario_id"],
            "scenario": s["scenario_label"],
            "benefit_drivers": round(benefit, 3),
            "cost_drivers": round(cost, 3),
            "LJI": round(index, 3),
            "lower_threshold": LJI_LOWER_THRESHOLD,
            "upper_threshold": LJI_UPPER_THRESHOLD,
            "design_implication": preferred_architecture(index),
        })

    rep_df = pd.DataFrame(all_rep_rows)
    summary_df = pd.DataFrame(summary_rows)
    lji_df = pd.DataFrame(lji_rows)
    threat_df = pd.DataFrame(THREAT_ROWS, columns=["threat_or_failure_mode", "A1 Central audit", "A2 Hash log", "A3 Ledger-like", "interpretation"])
    sensitivity_df = generate_sensitivity_table(params, scenarios)

    params_df.to_csv(out_tables / "table_parameter_register.csv", index=False)
    scenarios.to_csv(out_tables / "table_scenario_matrix.csv", index=False)
    rep_df.to_csv(out_tables / "replication_level_event_counts.csv", index=False)
    summary_df.to_csv(out_tables / "table_main_results.csv", index=False)
    threat_df.to_csv(out_tables / "table_threat_scenarios.csv", index=False)
    lji_df.to_csv(out_tables / "table_lji.csv", index=False)
    sensitivity_df.to_csv(out_tables / "table_sensitivity_summary.csv", index=False)

    make_figures(summary_df, lji_df, out_figs)

    return {
        "parameters": params_df,
        "scenarios": scenarios,
        "main_results": summary_df,
        "threats": threat_df,
        "lji": lji_df,
        "sensitivity": sensitivity_df,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]), help="Project root directory")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    results = run_simulation(root)
    print("TEA-Sim run complete.")
    for name, df in results.items():
        print(f"\n[{name}]")
        print(df.head(12).to_string(index=False))


if __name__ == "__main__":
    main()
