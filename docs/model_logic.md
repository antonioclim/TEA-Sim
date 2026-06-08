# TEA-Sim Model Logic

## Event count model

For each replication and scenario:

- Daily integrity anchors = patients × days.
- Daily provenance assertions = patients × days.
- Consent grants = patients.
- Revocations = Binomial(patients, revocation_probability).
- Access events = Poisson(patients × days × access_rate).
- Total evidence objects = anchors + provenance + consent grants + revocations + access events.

The model treats revocation events as the implemented form of consent-state transition evidence. It does not implement a separate policy-transition event stream.

## Storage model

Storage is derived from evidence object counts multiplied by architecture-specific evidence size. A3 is multiplied by the number of organisations to represent replicated ledger-like evidence.

## Write-cost units

Write-cost units are normalised relative units, not milliseconds. They are calculated from evidence object count, architecture-specific write factor and the replication burden of the storage architecture.

## Verification units

Verification units are normalised relative units, not milliseconds: A1 = access_events × 5.18; A2 = access_events × 7.18; A3 = access_events × 8.68.

## Privacy score

Privacy score is a proxy for metadata exposure. It is not a legal privacy assessment.

## Threat-coverage matrix

The threat table is a design-based coverage matrix. It is not a penetration test, formal proof or stochastic security experiment.

## Ledger Justification Index

The Ledger Justification Index is implemented as:

benefit = 0.45 × dispute_risk + 0.30 × organisational_norm + 0.25 × revocation_norm

cost = 0.28 + 0.22 × organisational_norm + 0.18 × revocation_norm + signature_penalty

LJI = benefit − cost

where organisational_norm = min((organisations − 1) / 4, 1), revocation_norm = min(revocation_probability / 0.08, 1), and signature_penalty = 0.17 for the ML-DSA-44-sized signature scenario and 0 otherwise. LJI is a decision-support heuristic, not an externally validated metric.

## Sensitivity analysis

Sensitivity is calculated for S2/A3 with one-at-a-time perturbations using expected event counts. It is reported as modelled changes in storage, write-cost units and verification units.
