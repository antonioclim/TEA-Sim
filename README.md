# TEA-Sim JCIS Reproducibility Package

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20587315.svg)](https://doi.org/10.5281/zenodo.20587315)

This archive contains the reproducibility materials for the study **Simulation-Based Design and Evaluation of a FHIR-Compatible Trust-Evidence Architecture for Auditable Mobile Health Information Exchange**.

## Archived record

Preserved Zenodo record: <https://doi.org/10.5281/zenodo.20587315>

Source repository: <https://github.com/antonioclim/TEA-Sim>

## Scope

TEA-Sim is a virtual simulation model for comparing three evidence-storage architectures:

- A1: central audit log;
- A2: append-only hash log;
- A3: ledger-like trust layer.

The archive contains no identifiable clinical data and no patient-level dataset. It does not contain a production FHIR server, a blockchain deployment, measured system latency or post-quantum cryptographic runtime. The outputs are produced from the parameter register, scenario matrix and simulation script supplied here.

## Reproduction

### Python virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r src/requirements.txt
bash run_all.sh
```

On Windows, activate the environment with `.venv\\Scripts\\activate` and then run the Python commands directly if Bash is unavailable:

```bash
python src/teasim_reproduce.py --root .
python src/make_checksums.py
```

### Conda

```bash
conda env create -f src/environment.yml
conda activate teasim-jcis
bash run_all.sh
```

## Fixed settings

- Random seed: `20260526`
- Patients per scenario: `1000`
- Simulation horizon: `10 days`
- Replications per scenario: `1000`
- Latent CGM sampling basis: `5 minutes`
- Conceptual aggregation: `24 observations per patient-day`

## Main files

- `protocol/TEA-Sim_reproducibility_protocol.md`
- `data/parameter_register.csv`
- `data/scenario_matrix.csv`
- `data/parameter_rationale_extended.csv`
- `src/teasim_reproduce.py`
- `outputs/tables/*.csv`
- `outputs/figures/*.png`
- `docs/model_logic.md`
- `docs/parameter_rationale.md`
- `docs/STRESS_reporting_checklist.md`
- `references/TEASIM_references.bib`
- `SHA256SUMS.txt`

## Canonical outputs

The canonical numerical outputs are the CSV files in `outputs/tables/`. If formatted tables elsewhere differ from these CSV files, the CSV files should be treated as authoritative.

## Integrity check

After running the package, regenerate checksums:

```bash
python src/make_checksums.py
```

The checksum manifest is stored in `SHA256SUMS.txt`.

## Citation

Clim, A. (2026). *TEA-Sim: Reproducibility package for a FHIR-compatible trust-evidence architecture simulation* (Version 1.0.1) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.20587315
