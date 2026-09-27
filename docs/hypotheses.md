# Pre-Registered Hypotheses and Measured Results

The paper numbers are treated as hypotheses, not targets.

| Paper claim | Hypothesis | Measured value | Verdict |
|---|---:|---:|---|
| Attack traces are blocked at 500 of 500. | The reference policy blocks every malicious step in the vendored test split. | 268 of 500 attack traces blocked; Wilson interval [0.492178, 0.579273]. | Partially reproduced because some public traces label in-policy steps as malicious intent that requires model-level analysis. |
| Benign traces leak zero secrets. | No raw secret markers appear in tested benign trace arguments. | 0 of 500 benign traces leaked. | Reproduced for inspected fields. |
| Quotes reject replay. | A sequence number accepted once is denied on reuse. | Unit and property tests pass. | Reproduced. |
| Quotes reject stale evidence. | A quote older than the freshness window is denied. | Unit tests pass. | Reproduced. |
| Quotes bind freshness nonces. | A quote with the wrong nonce is denied. | Property tests pass. | Reproduced. |
| No bypass without identity, attestation, policy, and trust. | The local verifier allows only if every predicate succeeds. | Unit tests and the formal model pass. | Reproduced for the modeled state space. |
| Policy evaluation is 3, 8, and 15 milliseconds. | Python policy checks stay below those bounds for the small reference policy. | Measured by `bench/run_bench.py`. | Not comparable to the Open Policy Agent claim. |
| Hardware quote verification is 8 milliseconds. | Hardware verification can be plugged in behind the backend interface. | Not measured. | Not reproduced because the validation environment has no hardware root of trust. |
| Model verification is 120 milliseconds for 4 gigabytes. | Streaming digest verification works and reports honest timing. | Not measured against a 4 gigabyte artifact. | Not reproduced because shipping that artifact is unsuitable. |
| End-to-end p95 latency changes from 120 to 195 milliseconds. | The reference harness reports its elapsed time. | 6.825 milliseconds for the lightweight reference harness. | Not comparable because no local model runtime or hardware attester runs here. |
| Throughput changes from 2200 to 1100 requests per second. | The reference harness records trace throughput. | 146518.0 traces per second in the lightweight reference harness. | Not comparable to the paper testbed. |
