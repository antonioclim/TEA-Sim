# Simulation reporting checklist

This checklist documents reporting completeness for the TEA-Sim model.

| Item | Location |
|---|---|
| Objective | `README.md`; `protocol/TEA-Sim_reproducibility_protocol.md` |
| Input parameters | `data/parameter_register.csv`; `data/parameter_rationale_extended.csv` |
| Scenario definitions | `data/scenario_matrix.csv` |
| Source code | `src/teasim_reproduce.py` |
| Random seed | `data/parameter_register.csv`; `src/teasim_reproduce.py` |
| Replication count | `data/parameter_register.csv` |
| Output tables | `outputs/tables/` |
| Output figures | `outputs/figures/` |
| Checksum manifest | `SHA256SUMS.txt` |
| Interpretation boundaries | `README.md`; `docs/model_logic.md` |
