# Model logic

The simulation compares three storage backends behind a stable TrustEvidence interface:

- A1 central audit log;
- A2 append-only hash log;
- A3 ledger-like replicated evidence backend.

The interface stores compact evidence artefacts concerning consent, provenance, access, integrity and consent-state transitions. Clinical payloads remain off-chain and are represented only by hashes or reference tokens in the model.

The model is a standards/interface simulation. It is not a FHIR conformance test, blockchain implementation, cryptographic runtime benchmark or clinical validation study.

Canonical formulas are implemented in `src/teasim_reproduce.py`.
