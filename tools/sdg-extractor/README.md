# SDG extractor

The extractor builds one CodeQL C/C++ database from the selected kernel
translation units and their recorded build commands. Kernel sources and
headers are the semantic input. The output follows
`docs/grammar-semantics-dependency-graph.md` in the workspace.

`KernelPaths.ql` supplies native, context-sensitive dataflow witnesses.
`KernelExtract.ql` supplies typed expressions, reaching definitions, actual
call bindings, field store/use relations, and control conditions. Field
names and nearby comparisons do not establish dependencies.

The assembler evaluates supported scalar expressions with Z3 bit vectors.
It preserves conversions, signed comparisons, arithmetic, masks, min/max
expansions, and short-circuit conditions. Mutation hints assign source
values. Internal fields are never mutation destinations.
Helper invocations retain separate parameters, local values, and read
observations. Inactive return branches do not require their helper calls to
execute. Extracted expression references are checked before assembly;
missing facts fail the run instead of producing dangling graph edges.

## Running

Run `install-dependencies.sh`, then use the managed `build` and `exec`
commands. The installer provides CodeQL and an isolated Python environment
containing the pinned Z3 dependency. `MORPHEUS_SDG_EXTRACTOR_PYTHON` can select
an existing compatible interpreter.
Query-pack compilation uses the shared `parallelism.sh` CPU policy.
Execution uses `MORPHEUS_SDG_EXTRACTOR_JOBS` (default 4), validated as a
positive integer; the same value controls TU compilation and CodeQL threads.
LLVM bitcode outputs also require `llvm-dis` from the build's LLVM toolchain.
`LLVM_DIS` can select that executable.

The normal execution creates a database. To reuse an existing database,
set `MORPHEUS_SDG_EXTRACTOR_DATABASE` to its directory. Execution verifies
every selected source and every archived file under the source root against
the current checkout before querying it. A mismatch fails the run.
Target byte order is recorded from the actual ELF or LLVM compilation
outputs. Reusing an older database can supply its original compile plan
through `MORPHEUS_SDG_EXTRACTOR_COMPILE_PLAN`, or captured target information
through `MORPHEUS_SDG_EXTRACTOR_TARGET_INFO`. Missing target information stays
unknown; the analyzer does not substitute the host's byte order.
The original compile plan also records signed-overflow options, including
the kernel's `-fno-strict-overflow`. Wrapping addition, subtraction,
multiplication, and negation follow that mode. When these flags are unknown,
an overflow-dependent rejection remains unresolved. Target information is
snapshotted with the queries and assembler for the run.

Outputs are `sdg-nodes.json`, `sdg-edges.json`, `sdg-rules.json`,
`sdg-candidates.json`, `sdg-diagnostics.json`, and the `sdg/` semantic rule
directory. The runner writes the requested result file with the managed
artifact names.

Each file in `sdg/` is a self-contained `sdg 1.2` document. It contains the
selected rule fields, every referenced node, every path edge including
cross-edges, the target edge, nested predicates, mutation hints, and the
assumption ledger. Records are JSON payloads after the record type so complex
predicates and source metadata are not flattened or discarded. The directory
`manifest.json` records the rule ID, SHA-256, node count, cross-edge count,
self-edge count, and target-edge count for every export.

The exporter consumes the current `sdg-rules.json`, `sdg-nodes.json`, and
`sdg-edges.json` schema directly. It validates node and edge references,
round-trips every file before writing it, rejects duplicate or dangling
records, and removes only files previously owned by its own manifest.

To export existing artifacts without rerunning CodeQL, use:

```sh
python scripts/convert_to_sdg.py \
  --rules /path/to/output/sdg-rules.json \
  --output /path/to/export
```

The sibling `sdg-nodes.json` and `sdg-edges.json` files are resolved by
default. Use `--nodes` and `--edges` to select them explicitly, and repeat
`--rule-id` to export specific rules. The assembler also invokes this
exporter automatically when writing managed results.

The file grammar is:

```text
sdg 1.2
rule <original-rule-id>
field <rule-field-name> <JSON-value>
node <node-id> <source|internal|sink> <JSON-metadata>
edge <edge-id> <src-node-id> <dst-node-id> <head> <JSON-metadata>
```

Every rule field except `id` is retained by name, including `path`,
`preconditions`, `target_state`, `mutation_hint`, and `validation`.
`target_state` preserves the separate target edge. Node metadata retains
types, locations, source bindings, and invocation identities; edge metadata
retains predicates and locations. `parse_sdg` reconstructs the original rule,
nodes, and edges. Unknown signedness and unresolved placements are retained.
JSON version 1.2 stores each edge once in `sdg-edges.json`; a rule's
`path.edges` lists those edge IDs. Native dependency alternatives are
retained in each path, including paths whose values cannot yet be solved.

## Interpreting results

The same kernel contract policy is used for data paths, source-dependent
control paths, and interrupt paths. `assumption-policy.json` records its
content hash and named return constraints. Every candidate carries this
policy identity before streaming, including candidates that fail during
resolution. `assumption-ledger.json` indexes each candidate's applied
contracts and unresolved prerequisites; `analysis-coverage.json` lists
every verified input file with endpoint counts and candidate statuses.
Publication requires both a connected source-to-sink dependency path and
derived mutations targeting its device sources. Neither is sufficient alone.
Path constraints, kernel assumptions, and unresolved conditions remain part
of the rule. Native paths are checked against extracted endpoint relations
and their connected steps; a source merely appearing in a witness is not
enough. Such a rule can be published even when Z3 cannot solve the complete
path or prove an exact target. Publication
does not promote its validation status. `sdg/` contains all published rules;
`sdg-conditional/` and `sdg-unresolved/` contain withheld candidates.
All candidates remain in `sdg-candidates.json`.

Z3 is a required dependency and the extraction always attempts symbolic
analysis. A timeout, unknown result, or unsupported operation leaves the
directional guidance available. A supported contradiction (`unsat`) is
different from a failed solve and remains rejected. `mutation_hint` contains
the basic alternatives; `enhancement.mutation_hint` retains any concrete
source assignments previously found by Z3. Existing `validation` and proof
records retain their exact meaning. There is one rule and one pipeline.

Hints include comparison boundaries, checked increases/decreases, bit masks,
and registered interrupt delivery. A lossy or unresolved computation retains
its graph and can guide source exploration in both directions; this does not
claim monotonic behavior at the sink. Alternatives are not a conjunction:
consumers select an action and recheck the full path predicates. No hint
writes an internal kernel value. `mutation-hints.csv` indexes these actions.

The version 2 assumption policy lists function return contracts and the
permitted kinds of kernel path assumptions. `validation.assumption_ledger`
records every applied condition: call return predicates, required kernel
state, callback selection, interrupt delivery, and memory-object validity.
`path-assumptions.csv` provides the per-rule list with predicates, kernel
functions, code locations, and device-input bindings; `path-assumptions.md`
summarizes it. Kernel state without a sufficient explicit condition remains
in `validation.unresolved_prerequisites`.

Path assumptions come only from original path conditions. Mixed conditions
are specialized with the rule's device inputs. Missing device observations
are solved under the original path and target, then added to source
assignments and mutation hints. Source-only conditions and target equalities
are never turned into kernel assumptions. Kernel witness values remain
diagnostic values in `validation.internal_state_witness`.

Implication checking requires a consistent antecedent and an unsatisfiable
counterexample query. The original obligation, exact assumption list, and
replayable SMT-LIB proof are retained. A return-success contract constrains
only success, such as `return != 0`; it does not fix an allocation address.
Listed callback, memory, and interrupt conditions are explicit workload
assumptions, not claims that the extractor proved them in the running kernel.

`sdg-rules.json` contains closed semantic rules that pass guidance checks.
Each published rule also appears as a full semantic file in `sdg/`, including
rules whose validation is still `conditional` or `unresolved`. Withheld rules
have explicit reasons in `sdg-diagnostics.json`. The older scalar runtime
format has additional placement and expression limits, recorded separately
in `runtime_export`; those limits do not block semantic guidance publication.

Compiler overflow builtins preserve both the truncated output write and
the overflow flag using extended bit-vector arithmetic. The enclosing
kernel helper's guards and saturation branches remain part of the path.

- `satisfiable` means the extracted scalar constraints have a solution.
- `valid_under_assumptions` means the typed source assignments plus the
  explicit kernel assumption ledger imply the selected path and target.
  The ledger explicitly lists the kernel path conditions and workload
  prerequisites used by that proof. Only device sources are mutation inputs.
- `conditional` means the solution also requires unresolved internal state
  or a transport callback selection recorded in the rule.
- Rejected targets contradict the selected path's supported computations
  or conditions. Unresolved paths stay in diagnostics with a reason.

These statuses do not establish complete kernel execution or a vulnerability.
`internal_state_witness` is a solver witness for prerequisites, not a list
of values the device mutator can write. Configuration offsets are tied to
the registered MMIO transport callback and retain that prerequisite.

To recheck an existing complete extraction under the configured path policy,
set `MORPHEUS_SDG_EXTRACTOR_RECHECK_FROM` to its output directory and run a
managed `exec` step with a separate output directory. The workspace provides
the `sdg-recheck-assumptions` workflow for this operation. Saved scalar
obligations are replayed without rerunning CodeQL, and each original export
is hash-checked before its unchanged node/edge records are copied. Function
return contracts must match the original policy. The source result remains
available, including its original publication status and proof evidence.

To derive and publish hints from a completed Z3 extraction, set
`MORPHEUS_SDG_EXTRACTOR_GUIDANCE_FROM` to its output directory and run the
workspace's `sdg-publish-guidance` workflow. It preserves the original Z3
results and assumptions and writes a separate output. The publication
threshold requires useful graph-derived guidance, not successful solving.

The semantic `sdg 1.2` format retains arbitrary boolean preconditions,
computations, internal state, and assumptions. The exporter accepts only the
current query schema. It preserves recorded status and validation evidence;
serializing a rule does not prove its assumptions or promote its status.
The final runtime input is `runtime-package/`, published as
`sdg-runtime-package`. Its manifest fixes file sizes and SHA-256 hashes.
`runtime.json` contains shared execution plans and rule identities;
`evidence.pack` stores compressed, deduplicated source records with integer
references. Each original semantic document can be reconstructed byte for
byte, including all assumptions, graph records, and validation evidence.
Runtime startup verifies both package files, then compiles only the execution
plans. Evidence is decoded on inspection. The package is portable and does
not require the original extraction directory.

The runtime accepts the full `sdg 1.2` format and the package. It applies
source mutation hints, rejects evaluably false path predicates, preserves
unknown prerequisites, and does not promote guidance to an exact target
proof. Unresolved source bindings exclude a rule from generation. IRQ actions
are ignored. A grammar run can require executable rules with `--require-sdg`
to prevent silently starting in random mode.
Legacy scalar exports remain in `runtime-sdg/` for compatibility.
An MMIO `offset` requires a proven mapping origin. An opaque pointer retains
its `relative_base`, `relative_offset` when constant, and address expression;
it is not exported as a fixed window offset. Dominating writes through the
same address base retain their values, addresses, and execution ordering in
each read's `access_context`. The legacy format cannot export that context.

The implementation is still incomplete against the specification. It now
extracts registered IRQ handlers and their synchronous control paths,
alongside MMIO data paths. Streaming-DMA support currently covers direct
single-buffer and page mappings with proven device-write direction, matching
CPU completion, page-view identity, mapped offsets, and address provenance.
Coherent-DMA reads require allocation
provenance and an acquire operation, and CPU-defined fields are excluded.
Coherent allocation lifetimes, aligned subregions, page-pool/scatter mappings,
asynchronous callback state, and full loop semantics still require work.

All native dependency alternatives are retained. Scalar solving considers
distinct endpoint/call/store witness contexts, including each control
endpoint and reachable call/store anchors. Context IDs are retained on
solved and unresolved rules. Cyclic alternatives stay in the graph; this
does not enumerate arbitrary loop iterations or prove every execution.
Unresolved contexts share a result only when every parameter binding,
field-store selection, and caller set consulted before the failure matches.
Absent bindings are compared too. The shared rule retains the other context
IDs and witness node sequences in `path.equivalent_contexts`; its full
alternative graph remains present. Progress reports count base flows and
witness contexts separately.
Conditional assignments
use control-flow ordering and guarded value alternatives. Unsupported
computations and ambiguous invocation contexts produce explicit unresolved
rules. Solver failure does not remove the underlying graph.

Branch conditions are input dependencies of conditional values and of
guarded returns. Both ordinary and GNU omitted-middle ternaries are exported
with explicit condition/then/else operands. Pointer resolution retains
guarded regions, offsets, and active bounds across assignments and helper
returns. Null alternatives have zero extent; ambiguous overlapping stores
and pointers without storage provenance remain unresolved.

Output-parameter effects retain guarded writes and their predecessor order
when extraction proves the effect is closed. Unmodeled scalar output writes
are explicit unknown internal values, so they cannot bypass their guards or
become source assignments. This permits analysis of the remaining supported
dependencies without claiming the unknown effect is resolved.
Multiple necessary control conditions for the same source-to-sink path are
stored together. Rule output is streamed while graph edges remain shared;
this does not impose a path-count or graph-size cutoff.

## Verification

With the installed Python interpreter, run:

```sh
python tests/run_semantic_tests.py --work-dir /path/to/test-work
```

This builds a real CodeQL database from regression C files, runs both
queries, and executes every generated source assignment through compiled C
to compare the observed sink operand with the rule's target. The fixtures
cover inversions, early returns, optional failure branches, short-circuiting,
casts, signedness, macro scopes, cross-file calls, separate instances, and
overwritten values.

To check exported rules with the actual runtime implementation:

```sh
python tests/check_runtime.py \
  --libafl-root /path/to/libafl/source \
  --rules /path/to/output/runtime-package \
  --work-dir /path/to/runtime-test-work --semantic
```

The harness imports the runtime's parser, generator, lowering, lifting, and
mutation code directly. Semantic checks exercise each executable rule with
8 random seeds, encoding/decoding, stored placements, and 32 generator/mutator
integration cases. It also restores sample evidence documents and compares
their runtime behavior. Use `--tests` for unit tests or `--release` for an
optimized checker. These checks do not execute the kernel.

To package an existing complete extraction, set
`MORPHEUS_SDG_EXTRACTOR_PACKAGE_FROM` to its `sdg/` directory and run the
workspace's `sdg-package` workflow. The original extraction remains intact.

To verify a completed, unfiltered kernel extraction, use the installed Python
interpreter with Z3:

```sh
python tests/check_kernel_semantics.py --output /path/to/output
```

This checks actual extracted overflow-builtin boundary cases, every semantic
export's hash and reconstructed rule/node/edge records, the shared assumption
policy and ledger, retained equivalent-context witnesses, and input coverage.
It also replays recorded assumption proofs and checks publication against the
recorded threshold. To check guidance derivations, graph round trips, retained
Z3 records, and mutation boundary cases, run:

```sh
python tests/check_guidance.py --output /path/to/output \
  --original /path/to/original-extraction
```

Verification prints
progress to stderr and a final JSON result to stdout; a progress record alone
does not establish completion. These checks validate the artifacts and their
recorded proof claims, without establishing full kernel reachability.
