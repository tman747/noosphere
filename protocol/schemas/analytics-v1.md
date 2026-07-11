# NOOS Experimental Analytics v1

Status literals are consensus-independent application metadata:

- universal `M-HDF`: `RETIRED`;
- surviving estimator: `M-HDF-ENERGY`;
- algorithm-transition/FMM mode: `SHADOW_ONLY`;
- stale or challenged profile credit: `ZERO_SHADOW_CREDIT`.

No object in this schema is accepted by Braid, Ground, Witness Ring, Lumen issuance, proposal weight, or finality. Analytics APIs return `ShadowObservation<T>` only. There is no conversion to a state delta, token amount, or consensus weight.

## M-HDF-ENERGY

`IntegerResidualV1` is `(rows:u32, cols:u32, values:[i64; rows*cols])`, row-major. Both dimensions MUST be nonzero powers of two. Its commitment is

`BLAKE3("NOOS/ANALYTICS/HDF-RESIDUAL/V1" || rows_le || cols_le || each_i64_le)`.

The residual MUST be committed before independent row signs, column signs, and sampled coordinates are disclosed. Every sign is exactly `-1` or `+1`; coordinate sampling is with replacement. Implementations apply the signs before an exact, unnormalized, two-sided integer Walsh-Hadamard transform. For `s` samples the output rational is

`estimate = sum(transformed_coordinate^2) / s`.

This equals the normalized theorem statistic because the `rows*cols` normalization cancels. All square accumulation is checked `u128`; overflow rejects. The only claim is unbiased residual-energy estimation with

`Var(estimate) <= 8 * ||E||_F^4 / s`.

It explicitly claims neither universal coordinate-detection dominance nor stronger exact Freivalds acceptance. Characteristic-two use is prohibited absent a separately registered invertible transform. Permanent negative regressions include characteristic-two collapse, flat-error worsening (miss probability `0 -> 3/4`), spike/flat duality, post-challenge adaptation, and post-transform quantization-floor loss.

## Shadow algorithm-transition auction

`WholeAttemptMeasurementV1` binds profile/submission IDs, algorithm family, independent implementation family, credited-work units, energy in integer microjoules, latency in microseconds, and booleans proving commitment/proof cost and deliverable materialization were included. Zero measurements reject.

The closed v1 algorithm-family set is `Naive`, `Tiled`, `StrassenFamily`, `FftFmm`, `CachedOperand`, `SparseStructured`, and `CustomHardware`. Tournaments MUST include all families relevant to the registered profile.

A material submission immediately changes only that profile's shadow credit to `ZERO_SHADOW_CREDIT`. A strategy has a disqualifying advantage exactly when

`candidate_work * baseline_energy * 100 > baseline_work * candidate_energy * 105`.

Missing commitment/proof cost or a non-materialized deliverable also forces zero. Demand starvation for one registered retarget half-life forces zero. A successor calibration requires two distinct implementation families reproducing energy within 10%; this reports shadow calibration only and cannot restore production influence. Past settlements are never reinterpreted.
