# STRESS-Oriented Reporting Checklist for TEA-Sim

| Element | Location in archive | Completed |
|---|---|---|
| Objectives | `protocol/TEA-Sim_reproducibility_protocol.md` | Yes |
| Conceptual model | `docs/model_logic.md` | Yes |
| Input data and assumptions | `data/parameter_register.csv`; `docs/parameter_rationale.md` | Yes |
| Scenario definitions | `data/scenario_matrix.csv` | Yes |
| Simulation algorithm | `src/teasim_reproduce.py` | Yes |
| Random seed | `data/parameter_register.csv`; `src/teasim_reproduce.py` | Yes |
| Number of replications | `data/parameter_register.csv`; protocol | Yes |
| Output metrics | protocol; source code; output tables | Yes |
| Verification | run script, inspect output tables, compare checksums | Yes |
| Validation boundary | protocol; parameter rationale | Yes |
| Reproducibility artefacts | README, environment files, source code, outputs, checksum manifest | Yes |
