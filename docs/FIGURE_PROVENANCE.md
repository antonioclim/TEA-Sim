# Figure provenance

The manuscript figures are generated deterministically by the reproducibility scripts.

- Figure 1 is generated from `data/figure_specs/figure_1_nodes.csv`, `data/figure_specs/figure_1_edges.csv`, `data/figure_specs/figure_1_groups.csv` and `data/figure_specs/figure_1_legend.csv`.
- Figure 2 is generated from `outputs/tables/table_main_results.csv` as a storage-burden plot.
- Figure 3 is generated from `outputs/tables/table_lji.csv` as a Ledger Justification Index plot.
- Auxiliary repository figures are generated from the canonical output tables in `outputs/tables/`.

Running `bash run_all.sh` regenerates the canonical tables, figure files and `SHA256SUMS.txt`.
