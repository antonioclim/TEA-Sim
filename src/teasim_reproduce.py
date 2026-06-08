import argparse
import csv
import struct
import zlib
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ARCHITECTURES = ["A1 Central audit", "A2 Hash log", "A3 Ledger-like"]
SCENARIO_ORDER = ["S1", "S2", "S3", "S4", "S5"]

THREAT_ROWS = [
    ["Payload modified after anchoring", "High if commitment exists", "High", "High", "All architectures can detect this if payload commitments are preserved."],
    ["Ordinary audit-row deletion", "Medium", "High", "Very high", "Hash continuity and replicated evidence improve detection."],
    ["Malicious central-administrator deletion", "Low", "Medium-high", "High", "This is the main scenario where A3 has a clear advantage."],
    ["Access after consent revocation", "Medium-high", "High", "High", "All require correct consent-state modelling; A3 improves independent verifiability."],
    ["Policy-version mismatch", "Medium-high", "High", "High", "A2 and A3 better preserve temporal policy evidence."],
    ["Interorganisational dispute", "Low-medium", "Medium", "High", "A3 is most defensible when no mutually trusted audit operator exists."],
    ["Metadata exposure risk", "Low-medium", "Medium", "High", "The privacy cost of A3 must be mitigated by minimisation and pseudonymisation."],
]


def read_parameter_table(data_dir: Path):
    df = pd.read_csv(data_dir / "parameter_register.csv")
    params = {}
    for _, row in df.iterrows():
        key = row["parameter"]
        value = row["value"]
        try:
            params[key] = float(value)
        except ValueError:
            params[key] = value
    return df, params


def percentile_interval(values, low=2.5, high=97.5):
    lo, hi = np.percentile(values, [low, high])
    return int(round(lo)), int(round(hi))


def simulate_event_counts(scenario_row, params, rng):
    patients = int(params["patients_per_scenario"])
    days = int(params["simulation_horizon_days"])
    obs_per_day = int(params["aggregated_observations_per_patient_day"])
    rev_p = float(scenario_row["revocation_probability_over_horizon"])
    access_rate = float(scenario_row["access_rate_per_patient_day"])
    daily_integrity_anchors = patients * days
    daily_provenance_assertions = patients * days
    consent_grants = patients
    revocations = rng.binomial(patients, rev_p)
    access_events = rng.poisson(patients * days * access_rate)
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


def expected_event_counts(scenario_row, params, patients=None, days=None, organisations=None, access_rate=None, revocation_probability=None, signature_profile=None):
    p = int(patients if patients is not None else params["patients_per_scenario"])
    d = int(days if days is not None else params["simulation_horizon_days"])
    obs_per_day = int(params["aggregated_observations_per_patient_day"])
    rev_p = float(revocation_probability if revocation_probability is not None else scenario_row["revocation_probability_over_horizon"])
    acc = float(access_rate if access_rate is not None else scenario_row["access_rate_per_patient_day"])
    revocations = p * rev_p
    access_events = p * d * acc
    anchors = p * d
    provenance = p * d
    consents = p
    evidence = anchors + provenance + consents + revocations + access_events
    observations = p * d * obs_per_day
    return {
        "daily_integrity_anchors": anchors,
        "daily_provenance_assertions": provenance,
        "consent_grants": consents,
        "revocations": revocations,
        "access_events": access_events,
        "evidence_objects": evidence,
        "conceptual_observations": observations,
    }


def evidence_size_bytes(architecture, orgs, profile, params):
    if profile == "classical":
        if architecture == "A1 Central audit":
            return params["trust_evidence_a1_classical_bytes"], 1
        if architecture == "A2 Hash log":
            return params["trust_evidence_a2_classical_bytes"], 1
        return params["trust_evidence_a3_classical_bytes_per_org"], orgs
    if profile == "mldsa44":
        if architecture == "A1 Central audit":
            return params["trust_evidence_a1_mldsa44_bytes"], 1
        if architecture == "A2 Hash log":
            return params["trust_evidence_a2_mldsa44_bytes"], 1
        return params["trust_evidence_a3_mldsa44_bytes_per_org"], orgs
    raise ValueError(f"Unknown signature profile: {profile}")


def storage_mb(evidence_objects, architecture, orgs, profile, params):
    b, multiplier = evidence_size_bytes(architecture, orgs, profile, params)
    return evidence_objects * b * multiplier / 1_000_000


def write_cost_units(evidence_objects, architecture, orgs, params):
    if architecture == "A1 Central audit":
        return evidence_objects * params["write_factor_a1"]
    if architecture == "A2 Hash log":
        return evidence_objects * params["write_factor_a2"]
    return evidence_objects * params["write_factor_a3"] * orgs


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
            kept.append(data[offset:offset + 12 + length])
        offset += 12 + length
        if chunk_type == b"IEND":
            break
    path.write_bytes(b"".join(kept))


def save_figure(fig, path: Path, dpi=200):
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)
    strip_png_text_chunks(path)


def compute_expected_summary(scenario_row, architecture, params, overrides=None):
    overrides = overrides or {}
    orgs = int(overrides.get("organisations", scenario_row["organisations"]))
    profile = overrides.get("signature_profile", scenario_row["signature_profile"])
    counts = expected_event_counts(
        scenario_row,
        params,
        patients=overrides.get("patients"),
        days=overrides.get("days"),
        access_rate=overrides.get("access_rate"),
        revocation_probability=overrides.get("revocation_probability"),
    )
    ev = counts["evidence_objects"]
    mb = storage_mb(ev, architecture, orgs, profile, params)
    wc = write_cost_units(ev, architecture, orgs, params)
    vu = verification_units(counts["access_events"], architecture, params)
    return {
        "evidence_objects": ev,
        "storage_mb": mb,
        "write_cost_units": wc,
        "verification_units": vu,
    }


def run_sensitivity(root, scenarios, params):
    s2 = scenarios.loc[scenarios["scenario_id"] == "S2"].iloc[0]
    arch = "A3 Ledger-like"
    base = compute_expected_summary(s2, arch, params)
    perturbations = [
        ("Signature profile", "Classical to ML-DSA-44-sized evidence", {"signature_profile": "mldsa44"}),
        ("Patient count", "-50%", {"patients": int(params["patients_per_scenario"] * 0.5)}),
        ("Patient count", "+50%", {"patients": int(params["patients_per_scenario"] * 1.5)}),
        ("Simulation horizon", "-50%", {"days": int(params["simulation_horizon_days"] * 0.5)}),
        ("Simulation horizon", "+50%", {"days": int(params["simulation_horizon_days"] * 1.5)}),
        ("Organisational multiplicity", "3 organisations to 2", {"organisations": 2}),
        ("Organisational multiplicity", "3 organisations to 4", {"organisations": 4}),
        ("Access rate", "-50%", {"access_rate": float(s2["access_rate_per_patient_day"]) * 0.5}),
        ("Access rate", "+50%", {"access_rate": float(s2["access_rate_per_patient_day"]) * 1.5}),
        ("Revocation probability", "-50%", {"revocation_probability": float(s2["revocation_probability_over_horizon"]) * 0.5}),
        ("Revocation probability", "+50%", {"revocation_probability": float(s2["revocation_probability_over_horizon"]) * 1.5}),
    ]
    rows = []
    for driver, perturbation, overrides in perturbations:
        x = compute_expected_summary(s2, arch, params, overrides)
        rows.append({
            "base_scenario": "S2",
            "base_architecture": arch,
            "driver": driver,
            "perturbation": perturbation,
            "storage_mb_base": round(base["storage_mb"], 1),
            "storage_mb_perturbed": round(x["storage_mb"], 1),
            "delta_storage_mb": round(x["storage_mb"] - base["storage_mb"], 1),
            "write_cost_units_base": int(round(base["write_cost_units"])),
            "write_cost_units_perturbed": int(round(x["write_cost_units"])),
            "delta_write_cost_units": int(round(x["write_cost_units"] - base["write_cost_units"])),
            "verification_units_base": int(round(base["verification_units"])),
            "verification_units_perturbed": int(round(x["verification_units"])),
            "delta_verification_units": int(round(x["verification_units"] - base["verification_units"])),
        })
    return pd.DataFrame(rows)


def run_simulation(root: Path):
    data_dir = root / "data"
    out_tables = root / "outputs" / "tables"
    out_figs = root / "outputs" / "figures"
    out_tables.mkdir(parents=True, exist_ok=True)
    out_figs.mkdir(parents=True, exist_ok=True)
    params_df, params = read_parameter_table(data_dir)
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
                "write_cost_units": int(round(wc)),
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
    threats_df = pd.DataFrame(THREAT_ROWS, columns=["scenario", "A1 Central audit", "A2 Hash log", "A3 Ledger-like", "interpretation"])
    sensitivity_df = run_sensitivity(root, scenarios, params)

    params_df.to_csv(out_tables / "table_parameter_register.csv", index=False)
    scenarios.to_csv(out_tables / "table_scenario_matrix.csv", index=False)
    rep_df.to_csv(out_tables / "replication_level_event_counts.csv", index=False)
    summary_df.to_csv(out_tables / "table_main_results.csv", index=False)
    threats_df.to_csv(out_tables / "table_threat_coverage_matrix.csv", index=False)
    lji_df.to_csv(out_tables / "table_lji.csv", index=False)
    sensitivity_df.to_csv(out_tables / "table_sensitivity_expected_value.csv", index=False)

    # Figure 1: storage overhead, sorted by S1-S5
    pivot = summary_df.pivot(index="scenario_id", columns="architecture", values="storage_mb").loc[SCENARIO_ORDER]
    fig, ax = plt.subplots(figsize=(9, 5))
    pivot.plot(kind="bar", ax=ax)
    ax.set_title("Modelled storage overhead under evidence-storage architectures")
    ax.set_xlabel("Scenario")
    ax.set_ylabel("Storage overhead (MB)")
    ax.set_xticklabels(SCENARIO_ORDER, rotation=0)
    save_figure(fig, out_figs / "figure_storage_mb.png")

    # Figure 2: write cost
    pivot_wc = summary_df.pivot(index="scenario_id", columns="architecture", values="write_cost_units").loc[SCENARIO_ORDER]
    fig, ax = plt.subplots(figsize=(9, 5))
    pivot_wc.plot(kind="bar", ax=ax)
    ax.set_title("Normalised write-cost units under evidence-storage architectures")
    ax.set_xlabel("Scenario")
    ax.set_ylabel("Write-cost units")
    ax.set_xticklabels(SCENARIO_ORDER, rotation=0)
    save_figure(fig, out_figs / "figure_write_cost_units.png")

    # Figure 3: verification units
    pivot_vu = summary_df.pivot(index="scenario_id", columns="architecture", values="verification_units").loc[SCENARIO_ORDER]
    fig, ax = plt.subplots(figsize=(9, 5))
    pivot_vu.plot(kind="bar", ax=ax)
    ax.set_title("Normalised verification units under evidence-storage architectures")
    ax.set_xlabel("Scenario")
    ax.set_ylabel("Verification units")
    ax.set_xticklabels(SCENARIO_ORDER, rotation=0)
    save_figure(fig, out_figs / "figure_verification_units.png")

    # Figure 4: LJI
    fig, ax = plt.subplots(figsize=(8, 4.5))
    lji_plot = lji_df.set_index("scenario_id").loc[SCENARIO_ORDER]
    lji_plot["LJI"].plot(kind="bar", ax=ax)
    ax.axhline(0.05, linestyle="--", linewidth=1)
    ax.axhline(-0.15, linestyle="--", linewidth=1)
    ax.set_title("Ledger Justification Index by scenario")
    ax.set_xlabel("Scenario")
    ax.set_ylabel("LJI")
    ax.set_xticklabels(SCENARIO_ORDER, rotation=0)
    save_figure(fig, out_figs / "figure_lji.png")

    # Figure 5: sensitivity delta storage
    fig, ax = plt.subplots(figsize=(9, 5))
    sens_plot = sensitivity_df.copy()
    sens_plot["label"] = sens_plot["driver"] + " (" + sens_plot["perturbation"] + ")"
    sens_plot.plot(kind="barh", x="label", y="delta_storage_mb", ax=ax, legend=False)
    ax.set_title("Expected-value sensitivity: delta storage for S2/A3")
    ax.set_xlabel("Delta storage (MB)")
    ax.set_ylabel("")
    save_figure(fig, out_figs / "figure_sensitivity_delta_storage.png")

    print("TEA-Sim run complete.")
    print("\n[main_results]\n" + summary_df.to_string(index=False))
    print("\n[lji]\n" + lji_df.to_string(index=False))
    print("\n[sensitivity]\n" + sensitivity_df.to_string(index=False))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    run_simulation(Path(args.root).resolve())


if __name__ == "__main__":
    main()
