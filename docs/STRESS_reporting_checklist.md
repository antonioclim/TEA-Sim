# STRESS-Oriented Reporting Checklist

This file summarises how the simulation package supports transparent reporting.

| Reporting item | Location in package |
|---|---|
| Simulation objective | `protocol/TEA-Sim_reproducibility_protocol.md`; `README.md` |
| Model boundary | `docs/model_logic.md`; `docs/parameter_rationale.md` |
| Inputs and assumptions | `data/parameter_register.csv`; `data/scenario_matrix.csv` |
| Stochastic settings | `data/parameter_register.csv`; `src/teasim_reproduce.py` |
| Replication count and seed | `data/parameter_register.csv` |
| Model equations | `docs/model_logic.md`; `src/teasim_reproduce.py` |
| Outputs | `outputs/tables/`; `outputs/figures/` |
| Reproduction command | `run_all.sh`; `README.md` |
| Integrity check | `SHA256SUMS.txt`; `src/make_checksums.py` |
| Limits of interpretation | `docs/parameter_rationale.md`; `protocol/TEA-Sim_reproducibility_protocol.md` |
