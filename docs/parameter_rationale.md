# Parameter rationale

The parameter register defines a compact scenario model for comparing evidence-storage backends. Parameters are classified as scenario assumptions, architecture assumptions, cryptographic-size assumptions or heuristic weights.

The model uses a 5-minute latent CGM sampling interval to represent high-frequency workload density. The evidence layer does not store each latent sample. A one-hour aggregation assumption produces 24 conceptual observations per patient day.

Evidence object sizes, replication factors and verification factors are modelled values. They support comparative architecture analysis rather than implementation benchmarking.

The ML-DSA-44-sized profile is used to examine artefact-size pressure under a post-quantum signature-size assumption. The package does not implement or benchmark ML-DSA runtime.
