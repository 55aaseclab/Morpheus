# `libafl_nesting`

`libafl_nesting` provides structured nested-fuzzing support for `LibAFL`.

It owns:

- `ScenarioInput`, which contains device override records only
- fixed-width override-seed encoding and decoding
- SDG rule-guided override generation and value mutation
- the guest stub artifact contract

## QEMU Bridge Build Support

Enable the `qemu-bridge-aarch64` feature to build against the patched
`qemu-libafl-bridge` backend through `libafl_qemu`.

This crate keeps the patched QEMU backend available for nested fuzzing, but it
does not define one single mandatory guest/host control ABI.
Instead, there are three practical communication models between the host-side
LibAFL runner and the guest stub:

1. Pure breakpoint model

   - The host sets a breakpoint at a known guest location such as the stub's
     `main()`.
   - When execution stops there, the host snapshots the VM and writes the
     serialized device override seed into guest-visible memory.
   - The host later detects iteration completion using another breakpoint,
     crash, or timeout.

   In this model, the guest stub does not actively signal LibAFL.
   Breakpoints only provide synchronization points.

2. `libvharness` model

   - The guest stub uses the `libvharness` command ABI.
   - The stub triggers a `SyncExit` or custom instruction back to the host.
   - The patched QEMU backend exposes this as a host-visible command boundary.
   - The host parses start, end, and related command arguments from the guest
     register ABI.

   In this model, the guest stub explicitly talks to the host through the
   `libafl_qemu` command path.

The `libafl_nesting` crate stays focused on device override seeds, encoding,
mutation, and the guest stub artifact. The guest and L2 QEMU perform the normal
virtio protocol; the seed never describes that protocol as a trace.
The exact communication model can evolve independently on top of the same
patched QEMU coverage backend.

## SDG Rule Configuration

The generator loads plain-text `.sdg` rule files from the directory named by
`MORPHEUS_LIBAFL_SDG_RULES`. When the variable is unset the generator runs in
plain mode and draws initial scenarios from its random generator without
reading any rule directory.

```text
MORPHEUS_LIBAFL_SDG_RULES=<rules-directory>
MORPHEUS_LIBAFL_DISABLE_SDG=true|false
```

Setting `MORPHEUS_LIBAFL_DISABLE_SDG` to a truthy value forces plain mode
even when a rule directory is named, so a plain evaluation stays plain
regardless of an ambient rule variable in the caller's shell.

The directory may contain legacy scalar rules, full `sdg 1.2` exports, or a
final `sdg-runtime-package`. Packages verify their file hashes and share
execution plans; their evidence archive restores the original documents on
inspection. Only external source values are lowered to the wire.

Full semantic rules use source mutation hints and reject path predicates
that evaluate to false. Unknown kernel prerequisites retain their recorded
status; generation does not establish an exact target proof. Rules requiring
unresolved source bindings are reported and excluded. IRQ actions are
ignored. Empty or wholly blocked rule sets select random fallback unless the
harness is configured with `MORPHEUS_LIBAFL_REQUIRE_SDG=true`.

The harness logs loaded/executable rule counts. When initial seed files are
provided in grammar mode, it also adds four generated semantic seeds so
rule-aware mutation has metadata for corpus entries.

## Semantic metadata sidecar

Rule-aware mutation never guesses semantic placement from the wire layout.
It reads the `SemanticScenario` recorded for the exact seed bytes from the
shared metadata store, keyed by the SHA-256 of the encoded `ScenarioInput`:

```text
MORPHEUS_LIBAFL_SDG_METADATA_DIR=<metadata-directory>
```

When the variable is unset the harness derives a sibling directory
`<corpus-name>.sdg-metadata` from `MORPHEUS_LIBAFL_CORPUS_DIR`. The sidecar
stays outside the corpus directory, so `OnDiskCorpus` never interprets a
metadata record as a testcase.

Each record is one `<digest>.json` file holding the semantic scenario with
its exact per-field placements. Registration writes the record atomically
(temp file plus rename in the same directory) before the record can be
evicted; lookups compute the digest from the exact current bytes, hit the
in-memory map first, and lazy-load the sidecar record on a miss. A record
whose internal digest disagrees with the computed digest or its file name is
rejected as stale, and a corrupt file is ignored. The in-memory map is
least-recently-used when a cap is configured; evicted records remain
recoverable from the sidecar.

Generator and mutator clones share one store, so seeds generated in one
process or client are usable by another through the shared sidecar
directory. Seeds without a record — imported or foreign wire-format seeds —
are never rule-aware mutated; they take the documented random fallback
instead.

Child metadata is persisted immediately when a mutation commits, before the
fuzzer evaluates the child into the corpus. A child that is never accepted
leaves a harmless orphan record: records are digest-keyed and can only ever
be found for those exact bytes. The encoded `ScenarioInput` remains the
authoritative replay bytes; the sidecar is mutation provenance only and
never affects replay or `SeedRecord` SHA verification.

## Seed-driven virtio device input

The L2 QEMU seed consumer is compiled into the version-scoped qemu-cca patch
used by the workflow. It consumes the same encoded `ScenarioInput` that the
guest stub hands to the L2 launcher; no QMP, vhost-user process, or separate
device backend is involved. The supported seed surfaces are:

```text
mmio_read_override(ADDRESS, WIDTH, VALUE);
queue_dma_write(op=OP, dir=DIRECTION, path=PATH, sequence=SEQ,
                queue=QUEUE, payload_len=PAYLOAD_LENGTH,
                used_len=USED_LENGTH);
```

`mmio_read_override` supplies an exact device-side MMIO result. A
`queue_dma_write` is armed by the seed and is consumed after the guest's
native virtqueue-notify MMIO. QEMU performs the descriptor walk, writes the
payload through the device DMA address space, publishes the supplied used
length, and raises the normal virtqueue notification. No virtio-net helper,
MMIO aperture, vhost-user process, or QMP command is involved.

Every replay outcome also contains `seed.trace.jsonl`. It is an observation
record, not an additional device input. It includes the decoded seed overrides,
all generic virtio-MMIO reads and writes, native seed MMIO/DMA events, and
Linux virtio DMA telemetry when available. Teardown and queue-progress events
remain visible in the report without being reinterpreted as new device
actions. CVE-specific QEMU profile patches are not needed by this path.

For debugging, LibAFL exec hides the outer L1 and nested L2 console streams by
default while retaining the complete raw stream in `launcher.stdout.log` for
runtime extraction. Pass `--show-console` (or set
`MORPHEUS_LIBAFL_SHOW_CONSOLE=true`) to display those streams as they arrive.
The LibAFL nesting workflow exposes the same boolean in its `libafl_exec` step;
Set
`workflows.nvirsh-qemu-arm64-cvm-libafl-nesting-fuzzing.metadata.console.show`
(or the corresponding workflow value) to `true` when running that
workflow interactively.

## SMP startup calibration

The workspace provides two small calibration workflows for selecting L1/L2
SMP.  Their default screening matrix is `L1={1,2,4} × L2={1,2}`, with three
repetitions per valid combination.  The nested-resource constraint
`L1 >= L2` is applied before launching a case, so `1/2` is never run.  Values
above the host's effective L1 capacity are recorded as unsupported rather
than silently clamped:

- the nvirsh workflow measures the direct nested-CVM launch path;
- the LibAFL workflow measures the same boundary through replay.

Both workflows run the configured SMP combinations and write a `benchmark.json`
report. The measured interval is:

```text
L2 qemu-exec-start -> Buildroot login:
```

The configured L2 run window is only a readiness timeout. It is never used as
the startup duration. Each case stops as soon as the Buildroot login prompt is
observed, and the report includes the host CPU model and the effective L1 SMP
cap.

For a different host, use the 1/1 median as the calibration point. If the
reference host's 1/1 median is `T_reference` and the new host measures
`T_new`, use:

```text
host_time_coefficient = T_new / T_reference
estimated_new_host_time = reference_combination_time * host_time_coefficient
```

The benchmark command accepts `--reference-baseline-ms` when the reference
1/1 value is known.  It also accepts `--reference-report` to load the
reference combination medians from an earlier `benchmark.json`.  In that
case the report writes the coefficient and an estimated duration for every
combination, so the new host need only run the small matrix.

The LibAFL calibration is the relevant choice for fuzzing throughput because
it includes the actual outer LibAFL nesting path. The direct nvirsh result is a
useful cross-check and isolates L2 boot behavior.

## Guest Stub Artifact

The crate exposes a guest stub binary target:

```bash
cargo build -p libafl_nesting --bin libafl_nesting_stub
```

Later runtime integration may copy that artifact into an L1 userspace image.
