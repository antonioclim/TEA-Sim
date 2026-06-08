# Methodological Rationale for TEA-Sim Parameters

This file records the rationale behind the scenario parameters and prevents scenario values from being interpreted as empirical clinical estimates.

## Boundary condition
TEA-Sim is a virtual simulation of architectural trade-offs. It is not a clinical cohort analysis, not an implementation benchmark and not a measurement of real health-system workload.

## Rationale by parameter group

### CGM sampling interval: 5 minutes
The 5-minute latent sampling interval reflects publicly documented continuous-glucose-monitoring characteristics used to calibrate the density of patient-produced measurements. It is not itself written to the trust-evidence layer. The model aggregates latent samples into hourly conceptual observations to preserve the architectural principle that high-frequency payload data should not become high-frequency trust evidence.

### Aggregation window: 1 hour
The one-hour aggregation window is a design assumption. It was selected to stress the separation between clinical payloads and evidence artefacts: the payload stream may be dense, but the evidence layer should record provenance and integrity events at a coarser governance-relevant granularity.

### Patients per scenario: 1,000
The 1,000-patient scale is a comparative stress-test population. It is large enough to expose storage and verification differences among architectures, but it is not claimed to represent a real hospital, trial or regional programme.

### Simulation horizon: 10 days
The ten-day horizon approximates a short remote-monitoring episode and keeps the simulation interpretable. It is not a claim about an optimal clinical monitoring duration.

### Access rates
Access rates are scenario-based governance loads. Low, medium and high values were chosen to separate direct-care, shared-care, secondary-use and high-dispute conditions. They are not measured clinical access frequencies.

### Revocation probabilities
Revocation probabilities are scenario-based stress parameters. They are included because consent-state transitions affect the evidentiary burden and the usefulness of temporal verification. They are not empirical estimates of patient revocation behaviour.

### Organisational multiplicity
The number of organisations is varied to test the condition under which a ledger-like trust layer becomes more defensible: absence of a mutually trusted audit operator across legally distinct entities.

### Dispute risk
Dispute risk is a scenario variable used to activate the central theoretical argument of the study. A ledger-like layer is not assumed to be useful everywhere; it becomes potentially justifiable only when dispute risk and cross-organisational verification needs increase.

### Signature profiles
The classical and ML-DSA-44-sized profiles are used to model storage and verification consequences of cryptographic agility. The study does not implement post-quantum cryptography or measure runtime. The model only examines how larger evidence signatures alter the relative cost of evidence-storage architectures.

## Parameter-control rule
Every parameter should retain one of the following source classes: observed/public, derived, standards-informed, scenario-based or model assumption. Any parameter lacking a rationale should be removed or moved to sensitivity analysis.
