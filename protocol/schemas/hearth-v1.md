# Hearth application schema v1

Hearth V0 and V1 are non-slashable. A household has exactly one external identity, bond account, fault stream, and payout stream. `HearthManifest` and `PartitionPlan` are signed; a membership change increments the generation and requires a new plan and conformance pass. A plan assigns contiguous stages to known devices, respects memory, and limits an integer boundary to 8192 bytes.

Interactive execution is LAN-only. WAN routes carry replica or batch jobs, use relay fallback when direct reachability fails, and use many-source seeding for content placement. Per-token pipelines with at least two hops and at least 50 ms RTT fail explicitly as `feature_disabled(E-HEARTH-05)`.

Availability uses basis points. Before E-HEARTH-03, stateful production custody requires `availability_bps >= 9000` (p>=0.9). Casual workers near 3000 (p≈0.3) receive only stateless/reissueable work or Chorus advisory tasks. Content shards reject corrupt bytes and are reconstructible only with at least `data_shards` distinct valid indices.

`UpdatePacket` and `ImmutableLearningRecord` are immutable. Promotion MUST name a distinct `SpeciesRevision` of the same Species.

The general dream market is killed. The only notebook is private, payout-free, non-authoritative, preregistered, commit-before-outcome, causally insulated, protected by an action firewall, reveal deadline, and globally one-shot realization nullifier. Any action influence invalidates it.
