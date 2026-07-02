# TEA-Sim reproducibility protocol

## Objective

Regenerate the canonical TEA-Sim tables and figures for the standards-compatible TrustEvidence interface model.

## Required files

- `data/parameter_register.csv`
- `data/scenario_matrix.csv`
- `src/teasim_reproduce.py`
- `src/make_checksums.py`
- `src/requirements.txt`

## Procedure

1. Create a clean Python environment.
2. Install dependencies from `src/requirements.txt`.
3. Run `bash run_all.sh` from the package root.
4. Confirm that the output tables exist in `outputs/tables/`.
5. Confirm that the output figures exist in `outputs/figures/`.
6. Confirm that `SHA256SUMS.txt` has been regenerated.

## Canonical outputs

- `outputs/tables/table_main_results.csv`
- `outputs/tables/table_lji.csv`
- `outputs/tables/table_sensitivity_summary.csv`
- `outputs/figures/figure_storage_mb.png`
- `outputs/figures/figure_lji.png`

## Boundaries

This protocol verifies deterministic script execution and output generation. It does not validate clinical performance, FHIR conformance, blockchain throughput, cryptographic runtime, privacy-law compliance or production deployability.
