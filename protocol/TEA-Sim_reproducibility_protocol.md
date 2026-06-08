# TEA-Sim Reproducibility Protocol

## Study title
Simulation-Based Design and Evaluation of a FHIR-Native Trust-Evidence Architecture for Auditable Mobile Health Information Exchange.

## Study type
Simulation-based design science research.

## Research questions
1. How can a FHIR-compatible mobile health information architecture formally separate clinical payloads from verifiable trust evidence?
2. How do central audit logs, append-only hash logs and ledger-like trust layers compare under simulated mHealth workloads?
3. Under which governance and workload conditions is a ledger-like trust-evidence layer justified?

## Data boundary
No identifiable patient data are used. No clinical deployment is conducted. The model uses synthetic patient-count assumptions, public wearable/continuous-glucose-monitoring sampling characteristics, standards-informed cryptographic signature-size parameters and scenario-based governance assumptions.

## Simulation settings
- Seed: 20260526
- Replications per scenario: 1000
- Patients per scenario: 1000
- Horizon: 10 days
- Architectures: A1, A2 and A3
- Scenarios: S1 to S5 as defined in `data/scenario_matrix.csv`

## Primary outputs
Evidence object count; storage MB; evidence/payload percentage; normalised verification units; privacy exposure proxy; threat-scenario coverage; Ledger Justification Index.

## Exclusions
The study does not report FHIR server performance, blockchain throughput, real cryptographic runtime, clinical outcomes, usability or patient behaviour.

## Confirmatory run
The confirmatory run is the execution of `bash run_all.sh` using the committed package state and fixed seed above.

## Registration status
This document is a reproducibility protocol for the confirmatory simulation package. It should not be described as a prospective pre-study registration unless it is locked before the final confirmatory run.

## Canonical outputs
The canonical numerical outputs are the CSV files produced by `bash run_all.sh` and stored in `outputs/tables/`.
