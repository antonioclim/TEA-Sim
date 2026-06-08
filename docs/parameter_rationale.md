# Methodological Rationale for TEA-Sim Parameters

## Boundary condition

TEA-Sim is a virtual simulation of architectural trade-offs. It is not a clinical cohort analysis, not an implementation benchmark and not a measurement of real health-system workload.

## Parameter groups

### CGM sampling interval

The 5-minute latent sampling interval reflects publicly documented continuous-glucose-monitoring characteristics used to calibrate the density of patient-produced measurements. It is not written to the trust-evidence layer. The model aggregates latent samples into hourly conceptual observations before evidence creation.

### Aggregation window

The one-hour aggregation window operationalises evidence minimisation. It prevents high-frequency sensor data from becoming a shadow payload repository in the evidence layer.

### Patients and horizon

The patient count and ten-day horizon are scenario-scaling assumptions. They are used to make differences between evidence-storage architectures visible. They are not presented as a real cohort size or deployment duration.

### Access and revocation parameters

Access frequency and revocation probability are scenario-based. They test how evidence volume and verification effort change under low-, medium- and high-complexity governance conditions.

### Organisational multiplicity

The number of organisations represents the increasing burden of cross-organisational accountability and replicated evidence. It is central to the comparison between central audit, hash-log and ledger-like storage.

### Signature profiles

The classical profile represents compact contemporary digital-signature evidence. The ML-DSA-44 profile models the impact of larger post-quantum-sized signatures on evidence storage and verification. It does not implement post-quantum cryptographic operations.

### Normalised cost units

Write and verification units are relative modelling units. They are not milliseconds, latency measurements, CPU measurements or throughput metrics.
