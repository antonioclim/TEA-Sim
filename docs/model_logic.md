# TEA-Sim Model Logic

## Event count model
For each replication and scenario:

- Daily integrity anchors = patients × days
- Daily provenance assertions = patients × days
- Consent grants = patients
- Revocations = Binomial(patients, revocation_probability)
- Access events = Poisson(patients × days × access_rate)
- Total evidence objects = anchors + provenance + consent grants + revocations + access events

## Storage model
Storage is derived from evidence object counts multiplied by architecture-specific evidence size. A3 is multiplied by the number of organisations to represent replicated ledger-like evidence.

## Verification units
Verification units are normalised units, not milliseconds: A1 = access_events × 5.18; A2 = access_events × 7.18; A3 = access_events × 8.68.

## Privacy score
Privacy score is a proxy for metadata exposure, not a legal privacy assessment.

## Ledger Justification Index
LJI is a heuristic: benefit drivers minus cost drivers. It is not claimed to be externally validated.
