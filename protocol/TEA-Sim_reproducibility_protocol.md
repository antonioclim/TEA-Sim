# TEA-Sim Reproducibility Protocol

## Purpose

This protocol defines the reproducibility boundary for TEA-Sim, a virtual simulation model comparing three trust-evidence storage architectures for auditable mobile health information exchange.

## Study boundary

The model is not a clinical deployment, not a production FHIR implementation, not a blockchain benchmark and not a post-quantum cryptographic runtime test. It is a simulation-based design science artefact for comparing evidence-storage trade-offs under transparent assumptions.

## Architecture variants

- A1: central audit log.
- A2: append-only hash log.
- A3: ledger-like trust layer.

Clinical payloads remain outside the evidence layer in all variants.

## Scenarios

The model uses five scenarios: low-complexity direct care, interorganisational shared care, secondary-use governance, high-dispute/high-revocation and crypto-agility transition.

## Reproducibility settings

- Random seed: 20260526.
- Replications per scenario: 1000.
- Patients per scenario: 1000.
- Simulation horizon: 10 days.

## Canonical outputs

The canonical numerical outputs are the CSV files in `outputs/tables/`. Formatted tables in articles or reports should be checked against these CSV files.

## Interpretation limits

Scenario-based parameters are not empirical estimates. Threat coverage is a design-based matrix. Write and verification costs are normalised model units and not production latency measurements.
