# TEA-Sim reproducibility package (v1.5.1)

TEA-Sim is a reproducibility package for the study **Standards-Compatible Trust-Evidence Interfaces for Auditable Health Information Exchange: A Simulation Study**.

The package contains source code, parameter registers, scenario definitions, generated CSV outputs, figures, methodological documentation and checksum manifests. It models a TrustEvidence interface that separates clinical payload custody from compact audit-evidence artefacts.

## Archived version and repository

Archived software version: https://doi.org/10.5281/zenodo.21134217.

Source repository: https://github.com/antonioclim/TEA-Sim

## Author and software creator

Antonio Clim, PhD  
Department of Economic Informatics and Cybernetics  
Bucharest University of Economic Studies  
Email: antonio.clim@csie.ase.ro  
ORCID: https://orcid.org/0000-0003-4745-0431  
Web of Science ResearcherID: AAC-7605-2019  
Scopus Author ID: 55753988600

## Scope

The model compares three evidence-storage backends behind the same TrustEvidence interface:

- A1 central audit log;
- A2 append-only hash log;
- A3 ledger-like replicated evidence backend.

The package does not include identifiable clinical data. It does not implement a production FHIR server, validate FHIR JSON resources, deploy a blockchain network, measure system latency, validate clinical outcomes or benchmark post-quantum cryptographic runtime.

## Reproduction entry point

The canonical entry point is:

```bash
bash run_all.sh
```

The script regenerates the canonical outputs in `outputs/tables/` and `outputs/figures/` and updates `SHA256SUMS.txt`.

## Key outputs

- `outputs/tables/table_main_results.csv`
- `outputs/tables/table_lji.csv`
- `outputs/tables/table_sensitivity_summary.csv`
- `outputs/figures/figure_storage_mb.png`
- `outputs/figures/figure_lji.png`
- `docs/FIGURE_PROVENANCE.md`

## Interpretation boundaries

The outputs are simulation artefacts under declared assumptions. FHIR is used as a conceptual standards boundary. Ledger-like storage is modelled as an evidence backend rather than as a complete blockchain implementation. ML-DSA-44 is used as an artefact-size profile rather than as a runtime implementation. Privacy and governance values are proxies, not legal-compliance scores.

## Licence

MIT License.
