#!/usr/bin/env python3
"""TEA-Sim reproducibility script.

This script produces the simulation tables and figures for TEA-Sim. It is not
a clinical implementation, FHIR server, blockchain deployment or cryptographic
runtime benchmark. It is a virtual simulation of architectural trade-offs.
"""
from pathlib import Path
import argparse
import struct
import zlib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

ARCHITECTURES = ["A1 Central audit", "A2 Hash log", "A3 Ledger-like"]

THREAT_ROWS = [
    ["Payload modified after anchoring", "High if commitment exists", "High", "High", "All architectures can detect this if payload commitments are preserved."],
    ["Ordinary audit-row deletion", "Medium", "High", "Very high", "Hash continuity and replicated evidence improve detection."],
    ["Malicious central-administrator deletion", "Low", "Medium-high", "High", "This is the main scenario where A3 has a clear advantage."],
    ["Access after consent revocation", "Medium-high", "High", "High", "All require correct consent-state modelling; A3 improves independent verifiability."],
    ["Policy-version mismatch", "Medium-high", "High", "High", "A2 and A3 better preserve temporal policy evidence."],
    ["Interorganisational dispute", "Low-medium", "Medium", "High", "A3 is most defensible when no mutually trusted audit operator exists."],
    ["Metadata exposure risk", "Low-medium", "Medium", "High", "The privacy cost of A3 must be mitigated by minimisation and pseudonymisation."],
]

SENSITIVITY_ROWS = [
    ["Signature profile", "Classical to ML-DSA-44-sized evidence", "Largest storage driver; approximately +164 MB in S2/A3."],
    ["Patient count", "±50%", "Nearly linear effect on evidence volume and storage."],
    ["Simulation horizon", "±50%", "Nearly linear effect because daily anchors and provenance scale by day."],
    ["Organisational multiplicity", "3 organisations to 2 or 4", "Large effect on A3 because replicated evidence scales with organisational count."],
    ["Access rate", "±50%", "Primary driver of verification effort; smaller effect on total storage."],
    ["Revocation probability", "±50%", "Low storage effect at tested rates but important for governance complexity and policy checking."],
]


def load_params(data_dir: Path):
    params_df = pd.read_csv(data_dir / "parameter_register.csv")
    params = {}
    for k, v in zip(params_df["parameter"], params_df["value"]):
        try:
            params[k] = float(v)
        except Exception:
            params[k] = v
    return params_df, params


def percentile_interval(values, lower=2.5, upper=97.5):
    return int(np.floor(np.percentile(values, lower))), int(np.ceil(np.percentile(values, upper)))


def simulate_event_counts(scenario, params, rng):
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


def storage_mb(evidence_objects, architecture, orgs, profile, params):
    if profile == "classical":
        if architecture == "A1 Central audit":
            b, multiplier = params["trust_evidence_a1_classical_bytes"], 1
        elif architecture == "A2 Hash log":
            b, multiplier = params["trust_evidence_a2_classical_bytes"], 1
        else:
            b, multiplier = params["trust_evidence_a3_classical_bytes_per_org"], orgs
    elif profile == "mldsa44":
        if architecture == "A1 Central audit":
            b, multiplier = params["trust_evidence_a1_mldsa44_bytes"], 1
        elif architecture == "A2 Hash log":
            b, multiplier = params["trust_evidence_a2_mldsa44_bytes"], 1
        else:
            b, multiplier = params["trust_evidence_a3_mldsa44_bytes_per_org"], orgs
    else:
        raise ValueError(f"Unknown signature profile: {profile}")
    return evidence_objects * b * multiplier / 1_000_000


def verification_units(access_events, architecture, params):
    if architecture == "A1 Central audit":
        return access_events * params["verification_factor_a1"]
    if architecture == "A2 Hash log":
        return access_events * params["verification_factor_a2"]
    return access_events * params["verification_factor_a3"]


def privacy_score(dispute_risk, architecture):
    if architecture == "A1 Central audit":
        return min(0.25 + 0.25 * dispute_risk + 0.015, 1.0)
    if architecture == "A2 Hash log":
        return min(0.40 + 0.25 * dispute_risk + 0.015, 1.0)
    return min(0.60 + 0.25 * dispute_risk + 0.015, 1.0)


def lji(dispute_risk, orgs, revocation_probability, signature_profile):
    org_norm = min((orgs - 1) / 4.0, 1.0)
    rev_norm = min(revocation_probability / 0.08, 1.0)
    signature_penalty = 0.17 if signature_profile == "mldsa44" else 0.0
    benefit = 0.45 * dispute_risk + 0.30 * org_norm + 0.25 * rev_norm
    cost = 0.28 + 0.22 * org_norm + 0.18 * rev_norm + signature_penalty
    return benefit, cost, benefit - cost


def preferred_architecture(lji_value):
    if lji_value < -0.15:
        return "A1 or A2 preferred; A3 disproportionate."
    if lji_value < 0.05:
        return "A2 usually proportionate; A3 conditional."
    return "A3 may be justified."


def strip_png_text_chunks(path: Path):
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
        crc = data[offset + 8 + length:offset + 12 + length]
        if chunk_type not in removable:
            if len(crc) == 4:
                kept.append(data[offset:offset + 12 + length])
            else:
                new_crc = struct.pack(">I", zlib.crc32(chunk_type + chunk_data) & 0xffffffff)
                kept.append(struct.pack(">I", length) + chunk_type + chunk_data + new_crc)
        offset += 12 + length
        if chunk_type == b"IEND":
            break
    path.write_bytes(b"".join(kept))


def save_figure(fig, path: Path, dpi=200):
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)
    strip_png_text_chunks(path)


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
                "verification_units": int(round(vu)),
                "privacy_score": round(ps, 2),
            })
        benefit, cost, index = lji(dispute, orgs, revp, profile)
        lji_rows.append({
            "scenario_id": s["scenario_id"],
            "scenario": s["scenario_label"],
            "benefit_drivers": round(benefit, 3),
            "cost_drivers": round(cost, 3),
            "LJI": round(index, 3),
            "design_implication": preferred_architecture(index),
        })
    rep_df = pd.DataFrame(all_rep_rows)
    summary_df = pd.DataFrame(summary_rows)
    lji_df = pd.DataFrame(lji_rows)
    threat_df = pd.DataFrame(THREAT_ROWS, columns=["scenario", "A1 Central audit", "A2 Hash log", "A3 Ledger-like", "interpretation"])
    sensitivity_df = pd.DataFrame(SENSITIVITY_ROWS, columns=["driver", "perturbation", "interpretation"])
    params_df.to_csv(out_tables / "table_parameter_register.csv", index=False)
    scenarios.to_csv(out_tables / "table_scenario_matrix.csv", index=False)
    rep_df.to_csv(out_tables / "replication_level_event_counts.csv", index=False)
    summary_df.to_csv(out_tables / "table_main_results.csv", index=False)
    threat_df.to_csv(out_tables / "table_threat_scenarios.csv", index=False)
    lji_df.to_csv(out_tables / "table_lji.csv", index=False)
    sensitivity_df.to_csv(out_tables / "table_sensitivity_summary.csv", index=False)
    for metric, fname, ylabel in [
        ("storage_mb", "figure_storage_mb.png", "Storage MB"),
        ("verification_units", "figure_verification_units.png", "Normalised verification units"),
        ("privacy_score", "figure_privacy_score.png", "Privacy exposure proxy"),
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
    ax.axvline(-0.15, linestyle="--")
    ax.axvline(0.05, linestyle="--")
    ax.set_xlabel("Ledger Justification Index")
    ax.set_title("Scenario-based Ledger Justification Index")
    save_figure(fig, out_figs / "figure_lji.png")
    fig, ax = plt.subplots(figsize=(10, 5.8))
    ax.axis("off")
    boxes = [
        (0.05, 0.70, "Mobile/wearable\ndata source"),
        (0.25, 0.70, "FHIR-compatible\nsemantic layer"),
        (0.45, 0.70, "Consent/policy\nstate model"),
        (0.65, 0.70, "TrustEvidence\ngenerator"),
        (0.85, 0.70, "Verifier /\nauditor"),
        (0.25, 0.32, "Off-chain payload\nrepository"),
        (0.49, 0.32, "A1 Central\naudit log"),
        (0.66, 0.32, "A2 Append-only\nhash log"),
        (0.84, 0.32, "A3 Ledger-like\ntrust layer"),
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
    ax.text(0.5, 0.08, "Clinical payloads remain off-chain; only compact trust evidence enters the simulated evidence-storage layer.", ha="center")
    save_figure(fig, out_figs / "figure_teasim_architecture.png")
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
        print(df.head(10).to_string(index=False))


if __name__ == "__main__":
    main()
