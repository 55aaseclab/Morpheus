//! Static semantic-dependency rules loaded from plain-text rule files.
//!
//! Condition lines keep the full canonical edge identity: source node,
//! destination node, head, and predicate. The canonical rule id on the
//! `rule` line is preserved verbatim and validated against the rule fields;
//! mismatches are identity conflicts and reject the rule.

use alloc::{string::String, vec::Vec};
use core::num::NonZeroUsize;

use libafl_bolts::rands::Rand;
use serde::{Deserialize, Serialize};

use crate::input::{CoherentAlloc, DmaSection, MmioSection, ScenarioInput, StreamUnit, WordModel};

#[path = "sdg_semantic.rs"]
pub mod semantic;

/// Semantic value held in a scenario. Width is enforced by the source node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Bytes(Vec<u8>),
}

impl Value {
    /// Little-endian integer interpretation for byte payloads.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Value::U8(v) => Some(v as u64),
            Value::U16(v) => Some(v as u64),
            Value::U32(v) => Some(v as u64),
            Value::U64(v) => Some(v),
            Value::Bytes(ref bytes) => {
                if bytes.is_empty() || bytes.len() > 8 {
                    return None;
                }
                let mut value = 0u64;
                for (index, byte) in bytes.iter().enumerate() {
                    value |= (*byte as u64) << (8 * index);
                }
                Some(value)
            }
        }
    }

    #[must_use]
    pub fn width_bits(&self) -> Option<u8> {
        match *self {
            Value::U8(_) => Some(8),
            Value::U16(_) => Some(16),
            Value::U32(_) => Some(32),
            Value::U64(_) => Some(64),
            Value::Bytes(ref bytes) => Some(bytes.len() as u8 * 8),
        }
    }

    /// Build a `Value` that fits `width_bits`. Out-of-domain values are
    /// rejected rather than clamped or truncated.
    pub fn from_u64(value: u64, width_bits: u8) -> Result<Value, String> {
        if width_bits == 0 || width_bits > 64 {
            return Err(format!("invalid width {width_bits}"));
        }
        let max = max_for_width(width_bits);
        if value > max {
            return Err(format!(
                "value {value} exceeds width {width_bits} domain (max {max})"
            ));
        }
        match width_bits {
            1..=8 => Ok(Value::U8(value as u8)),
            9..=16 => Ok(Value::U16(value as u16)),
            17..=32 => Ok(Value::U32(value as u32)),
            _ => Ok(Value::U64(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signedness { Unknown, Signed, Unsigned }

/// Dependency head: the source-level relationship kind of an edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Head {
    Guard,
    Dataflow,
    Bound,
    Offset,
    Call,
}

impl Head {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Head::Guard => "head_guard",
            Head::Dataflow => "head_dataflow",
            Head::Bound => "head_bound",
            Head::Offset => "head_offset",
            Head::Call => "head_call",
        }
    }

    #[must_use]
    pub fn from_str(name: &str) -> Option<Head> {
        match name {
            "head_guard" => Some(Head::Guard),
            "head_dataflow" => Some(Head::Dataflow),
            "head_bound" => Some(Head::Bound),
            "head_offset" => Some(Head::Offset),
            "head_call" => Some(Head::Call),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    /// Full semantic rule when loaded from sdg 1.2.
    pub semantic: Option<alloc::sync::Arc<semantic::SemanticRule>>,
    /// Canonical rule id, preserved verbatim from the extractor.
    pub name: String,
    pub nodes: Vec<Node>,
    pub preconditions: Vec<Condition>,
    pub trigger: Condition,
    pub mutation: Mutation,
}

impl Rule {
    /// Binding issues prevent execution, without discarding the published rule.
    pub fn runtime_blockers(&self) -> &[semantic::RuntimeBlocker] {
        self.semantic.as_ref().map_or(&[], |s| s.blockers.as_slice())
    }
    /// Find the node referenced by a condition.
    #[must_use]
    pub fn node_for(&self, name: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.name == name)
    }

    /// The variable the target-state predicate constrains.
    #[must_use]
    pub fn target_var(&self) -> &str {
        &self.trigger.dst
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub name: String,
    pub source: Source,
    pub width_bits: u8,
}

impl Node {
    /// The semantic field name: the last component of the node id.
    #[must_use]
    pub fn field_name(&self) -> &str {
        self.name.rsplit(':').next().unwrap_or(&self.name)
    }

    /// Canonical deterministic node id used for sorting and lowering order.
    /// The node id carries the full canonical form
    /// `<kind>:<identity>:<field>`; the field is its last component.
    #[must_use]
    pub fn canonical_id(&self) -> String {
        let field = self.field_name();
        match self.source {
            Source::Mmio { offset, size } => {
                format!("mmio:{}:{}:{}", offset, size, field)
            }
            Source::Coherent { offset, size } => {
                format!("coherent:{}:{}:{}", offset, size, field)
            }
            Source::Streaming { slot, offset, size } => {
                format!("streaming:{}:{}:{}:{}", slot, offset, size, field)
            }
        }
    }

    /// Maximum unsigned value that fits this node's declared width.
    #[must_use]
    pub fn max_value(&self) -> u64 {
        max_for_width(self.width_bits)
    }

    /// Access width of this node in bytes.
    #[must_use]
    pub fn size_bytes(&self) -> u8 {
        source_size(&self.source)
    }
}

#[must_use]
fn max_for_width(width_bits: u8) -> u64 {
    debug_assert!(width_bits > 0 && width_bits <= 64, "invalid width");
    if width_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << width_bits) - 1
    }
}

/// Maximum signed value of the node width, in two-complement terms.
#[must_use]
fn max_signed_for_width(width_bits: u8) -> i128 {
    debug_assert!(width_bits > 0 && width_bits <= 64, "invalid width");
    (1i128 << (width_bits - 1)) - 1
}

/// Minimum signed value of the node width.
#[must_use]
fn min_signed_for_width(width_bits: u8) -> i128 {
    debug_assert!(width_bits > 0 && width_bits <= 64, "invalid width");
    -1i128 << (width_bits - 1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    Mmio { offset: u32, size: u8 },
    Coherent { offset: u32, size: u8 },
    Streaming { slot: u8, offset: u32, size: u8 },
}

fn source_size(source: &Source) -> u8 {
    match *source {
        Source::Mmio { size, .. } | Source::Coherent { size, .. } | Source::Streaming { size, .. } => size,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Predicate {
    BitSet(u32),
    BitClear(u32),
    Eq(u64),
    Ne(u64),
    Lt(u64, Signedness),
    Gt(u64, Signedness),
    Le(u64, Signedness),
    Ge(u64, Signedness),
    InRange(u64, u64, Signedness),
}

impl Predicate {
    /// Whether the predicate is satisfied by `value` under the node width.
    /// Width is needed for bit predicates and signed comparisons.
    #[must_use]
    pub fn satisfied_by(&self, value: u64, width_bits: u8) -> bool {
        match *self {
            Predicate::BitSet(b) => {
                if b >= width_bits as u32 { return false; }
                (value & (1u64 << b)) != 0
            }
            Predicate::BitClear(b) => {
                if b >= width_bits as u32 { return false; }
                (value & (1u64 << b)) == 0
            }
            Predicate::Eq(v) => value == v,
            Predicate::Ne(v) => value != v,
            Predicate::Lt(v, s) => signed_value(value, width_bits, s) < signed_value(v, width_bits, s),
            Predicate::Gt(v, s) => signed_value(value, width_bits, s) > signed_value(v, width_bits, s),
            Predicate::Le(v, s) => signed_value(value, width_bits, s) <= signed_value(v, width_bits, s),
            Predicate::Ge(v, s) => signed_value(value, width_bits, s) >= signed_value(v, width_bits, s),
            Predicate::InRange(lo, hi, s) => {
                let sv = signed_value(value, width_bits, s);
                sv >= signed_value(lo, width_bits, s) && sv <= signed_value(hi, width_bits, s)
            }
        }
    }

    /// Whether the predicate's constants are representable under the node
    /// width and signedness. Signed relational bounds are two-complement
    /// encoded and ordered under signedness.
    #[must_use]
    pub fn in_domain(&self, width_bits: u8) -> bool {
        if width_bits == 0 || width_bits > 64 {
            return false;
        }
        let max = if width_bits == 64 { u64::MAX } else { (1u64 << width_bits) - 1 };
        match *self {
            Predicate::BitSet(b) | Predicate::BitClear(b) => b < width_bits as u32,
            Predicate::Eq(v) | Predicate::Ne(v) => v <= max,
            Predicate::Lt(v, s) | Predicate::Gt(v, s) | Predicate::Le(v, s) | Predicate::Ge(v, s) => {
                // Constants are two-complement encoded patterns; signed
                // predicates interpret them under signedness, so the full
                // bit-pattern range of the width is valid.
                let _ = s;
                v <= max
            }
            Predicate::InRange(lo, hi, s) => {
                if lo > max || hi > max {
                    return false;
                }
                if s == Signedness::Signed {
                    signed_value(lo, width_bits, s) <= signed_value(hi, width_bits, s)
                } else {
                    lo <= hi
                }
            }
        }
    }

    /// The comparison signedness of a relational predicate.
    #[must_use]
    pub fn signedness(&self) -> Signedness {
        match *self {
            Predicate::Lt(_, s) | Predicate::Gt(_, s) | Predicate::Le(_, s)
            | Predicate::Ge(_, s) | Predicate::InRange(_, _, s) => s,
            _ => Signedness::Unsigned,
        }
    }

    /// The scalar threshold of a boundary-style predicate.
    #[must_use]
    pub fn threshold(&self) -> Option<u64> {
        match *self {
            Predicate::Gt(v, _) | Predicate::Lt(v, _) | Predicate::Ge(v, _)
            | Predicate::Le(v, _) | Predicate::Eq(v) | Predicate::Ne(v) => Some(v),
            _ => None,
        }
    }
}

/// An edge: source node, destination node, dependency head, and predicate.
/// Self-edges have src == dst; cross-edges carry the full identity.
#[derive(Clone, Debug)]
pub struct Condition {
    pub src: String,
    pub dst: String,
    pub head: Head,
    pub predicate: Predicate,
}

impl Condition {
    /// The node the predicate constrains: the source for cross-edges, the
    /// target for self-edges (where src == dst).
    #[must_use]
    pub fn predicate_var(&self) -> &str {
        &self.src
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundarySide { Above, Below, Min, Max }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    SetBoundary(BoundarySide),
    SetValue(u64),
    FlipBit(u8),
    SetBits(u64),
    ClearBits(u64),
    Inc(u64),
    Dec(u64),
    SampleRange(u64, u64),
    Keep,
}

#[derive(Clone, Debug, Default)]
pub struct SemanticDependencyGraph { pub rules: Vec<Rule> }

/// Exact runtime placement of one semantic field: the DMA surface region
/// ordinal and the visit index the field's value occupies. The stored
/// region and visit are the only sound placement source: lowering and
/// mutation honor them verbatim, and no code may recover them from the wire
/// layout. Streaming DMA never carries a visit: mapped buffers fill once, so
/// their visit is 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Placement {
    pub region: u8,
    pub visit: usize,
}

/// A sparse semantic scenario: one target rule plus values, node metadata,
/// and exact runtime placements. The node map lets the lowerer handle
/// variables added by cross-rule mutation even when they are not declared by
/// the primary rule; the placement map preserves the exact region and visit
/// selected for each field, so mutation re-lowers to the same physical slot.
/// The scenario is mutation provenance: it lives beside the corpus input,
/// keyed by the SHA-256 of the exact encoded bytes, and is never part of the
/// wire format.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticScenario {
    pub target_rule: String,
    pub values: alloc::collections::BTreeMap<String, Value>,
    pub nodes: alloc::collections::BTreeMap<String, Node>,
    pub placements: alloc::collections::BTreeMap<String, Placement>,
    /// Protocol streaming slot -> chosen runtime region ordinal. Distinct
    /// slots never share a region.
    pub slot_regions: alloc::collections::BTreeMap<u8, u8>,
}

impl SemanticScenario {
    #[must_use]
    pub fn value(&self, name: &str) -> Option<&Value> {
        self.values.get(name)
    }

    pub fn set(&mut self, name: String, value: Value) {
        self.values.insert(name, value);
    }

    pub fn insert_node(&mut self, node: Node) {
        self.nodes.insert(node.name.clone(), node);
    }

    pub fn insert_placement(&mut self, name: &str, placement: Placement) {
        self.placements.insert(name.to_string(), placement);
    }
}

impl SemanticDependencyGraph {
    /// IRQ-only rules and sources without concrete bindings stay inspectable
    /// but are excluded from generation.
    pub fn has_executable_rules(&self) -> bool {
        self.rules.iter().any(|rule| rule.runtime_blockers().is_empty())
    }
    #[cfg(feature = "std")]
    pub fn from_dir(path: &std::path::Path) -> Result<Self, String> {
        if path.join("runtime.json").exists() || path.join("evidence.pack").exists() {
            return semantic::load_package(path);
        }
        // An empty but valid rule directory is not an error: the
        // integration selects the documented fallback random generation and
        // mutation when no rules are present.
        let mut rules = Vec::new();
        let mut pool = semantic::GraphPool::default();
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| format!("failed to read SDG rule directory {}: {e}", path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        // Deterministic rule loading order.
        entries.sort_by_key(|e| e.path());
        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) == Some("sdg") {
                rules.push(semantic::load_file(&path, &mut pool)?);
            }
        }
        // Duplicate canonical rule ids are identity conflicts; they are never
        // resolved by container order.
        let mut seen = alloc::collections::BTreeSet::new();
        for rule in &rules {
            if !seen.insert(canonical_rule_id(rule)) {
                return Err(format!("identity conflict: duplicate canonical rule id {}", rule.name));
            }
        }
        // Deterministic rule selection order: canonical rule id.
        rules.sort_by(|a, b| canonical_rule_id(a).cmp(&canonical_rule_id(b)));
        Ok(Self { rules })
    }

    /// Generate a semantic scenario for one rule. Each semantic field
    /// independently draws its random region and visit once, here, and the
    /// draws are recorded in the scenario for exact later reuse.
    pub fn generate<R: Rand>(&self, rand: &mut R) -> Result<SemanticScenario, String> {
        let rule = choose_rule(&self.rules, rand)?;
        if rule.semantic.is_some() { return semantic::generate(rule, rand); }
        let mut scenario = SemanticScenario {
            target_rule: rule.name.clone(),
            values: alloc::collections::BTreeMap::new(),
            nodes: alloc::collections::BTreeMap::new(),
            placements: alloc::collections::BTreeMap::new(),
            slot_regions: alloc::collections::BTreeMap::new(),
        };

        // Satisfy at least one precondition when the list is non-empty.
        if !rule.preconditions.is_empty() {
            let sorted = sorted_preconditions(rule);
            let idx = rand.below(unsafe { NonZeroUsize::new_unchecked(sorted.len()) });
            let cond = &sorted[idx];
            let node = rule.node_for(cond.predicate_var()).ok_or_else(|| format!("missing node {}", cond.predicate_var()))?;
            let value = generate_satisfying(&cond.predicate, node, None, rand)?;
            record_placement(&mut scenario, node, rand);
            scenario.values.insert(node.name.clone(), value);
            scenario.nodes.insert(node.name.clone(), node.clone());
        }

        // Move the target variable into the target state by executing the
        // rule's mutation hint; the revalidation below rejects rules whose
        // hint cannot reach the target state.
        let target_node = rule.node_for(rule.target_var()).ok_or_else(|| format!("missing trigger node {}", rule.target_var()))?;
        let target_value = apply_mutation_hint(&rule.trigger.predicate, target_node, &rule.mutation, None, rand)?;
        record_placement(&mut scenario, target_node, rand);
        scenario.values.insert(target_node.name.clone(), target_value);
        scenario.nodes.insert(target_node.name.clone(), target_node.clone());

        // Fill any remaining nodes with random values inside their width.
        let mut remaining: Vec<&Node> = rule.nodes.iter().filter(|n| !scenario.values.contains_key(&n.name)).collect();
        remaining.sort_by_key(|n| n.canonical_id());
        for node in remaining {
            let value = random_value_for_node(node, rand);
            record_placement(&mut scenario, node, rand);
            scenario.values.insert(node.name.clone(), value);
            scenario.nodes.insert(node.name.clone(), node.clone());
        }

        // Revalidate target state and at least-one precondition. A hint that
        // cannot reach the target state is an explicit rejection.
        let target_u64 = scenario.values.get(rule.target_var()).and_then(|v| v.as_u64()).unwrap_or(0);
        if !rule.trigger.predicate.satisfied_by(target_u64, target_node.width_bits) {
            return Err(format!(
                "generated target state does not satisfy {} trigger {}",
                rule.target_var(), hint_description(&rule.mutation)
            ));
        }
        if !rule.preconditions.is_empty() && !rule.preconditions.iter().any(|c| {
            rule.node_for(c.predicate_var()).is_some_and(|n| c.predicate.satisfied_by(scenario.values.get(c.predicate_var()).and_then(|v| v.as_u64()).unwrap_or(0), n.width_bits))
        }) {
            return Err("generated scenario satisfies no precondition".into());
        }

        Ok(scenario)
    }

    /// Rule-aware mutation of one exact stored semantic scenario.
    ///
    /// The caller supplies the scenario that was recorded for these exact
    /// input bytes; the rule is the scenario's own target rule. The target
    /// variable's bytes are updated at the stored placement, and everything
    /// else on the wire is preserved. Returns the mutated child scenario so
    /// the caller can register it for the child bytes. Returns `None` when
    /// the rule is unknown, the placement is stale, or the mutated state
    /// would violate the rule.
    pub fn mutate_scenario<R: Rand>(
        &self,
        rand: &mut R,
        input: &mut ScenarioInput,
        parent: &SemanticScenario,
    ) -> Option<SemanticScenario> {
        // Mutate the exact scenario that was recorded for these bytes; a
        // rule that is no longer in the graph makes the metadata stale.
        let rule = self.rules.iter().find(|r| r.name == parent.target_rule)?;

        if rule.semantic.is_some() { return semantic::mutate(rule, rand, input, parent); }

        let target_node = rule.node_for(rule.target_var())?;
        let placement = parent.placements.get(rule.target_var()).copied()?;
        // Reject stale metadata: the value stored at generation time must
        // still be readable at the stored placement.
        let current = read_node_value(input, target_node, placement)?;
        let stored = parent.values.get(rule.target_var())?.as_u64()?;
        if current != stored {
            return None;
        }
        let value = apply_mutation(current, target_node, &rule.trigger.predicate, &rule.mutation, rand).ok()?;

        // Work on a clone and commit only when the full state validates, so
        // conflicting mutations are skipped atomically.
        let mut candidate_input = input.clone();
        if set_node_value(&mut candidate_input, target_node, &value, placement).is_err() {
            return None;
        }

        // Target-state mutation must not modify precondition-only variables.
        // Revalidate the target state and at least one precondition.
        if !rule_state_satisfied(&candidate_input, rule, parent) {
            return None;
        }

        let mut child = parent.clone();
        child.values.insert(target_node.name.clone(), value);

        // Optional cross-rule merge: add the required secondary nodes and
        // satisfy both the primary rule and the complete secondary rule
        // (target state plus at least one precondition) without
        // contradicting the primary target state.
        if rand.below(unsafe { NonZeroUsize::new_unchecked(2) }) == 0 {
            // On conflict the merge is skipped atomically; the primary
            // mutation above remains valid.
            cross_merge(rand, rule, &mut candidate_input, &mut child, &self.rules);
        }

        if !candidate_input.is_valid() {
            return None;
        }
        if encode_scenarios_equal(&candidate_input, input) {
            return None;
        }
        *input = candidate_input;
        Some(child)
    }
}

/// Draw and record the runtime placement of one semantic field.
///
/// Every MMIO and coherent semantic field independently draws a random
/// target visit; coherent DMA also draws a random region per field. Fields
/// that happen to share `(aligned_offset, target_visit)` are mask-merged by
/// the lowerer; no visit ordering or count encodes semantic identity.
/// Streaming DMA draws one random runtime region per protocol slot group and
/// fills once, so its visit is 0.
fn record_placement<R: Rand>(scenario: &mut SemanticScenario, node: &Node, rand: &mut R) {
    let placement = match node.source {
        Source::Streaming { slot, .. } => {
            let region = match scenario.slot_regions.get(&slot) {
                Some(region) => *region,
                None => {
                    let used: Vec<u8> = scenario.slot_regions.values().copied().collect();
                    let region = random_region_excluding(&used, rand);
                    scenario.slot_regions.insert(slot, region);
                    region
                }
            };
            // A mapped streaming buffer fills once: its single word value
            // carries every slot field, mask-merged, so the visit is 0.
            Placement { region, visit: 0 }
        }
        Source::Coherent { .. } => {
            let region = random_region(rand);
            let visit = random_visit(rand);
            Placement { region, visit }
        }
        Source::Mmio { .. } => {
            let visit = random_visit(rand);
            Placement { region: 0, visit }
        }
    };
    scenario.insert_placement(&node.name, placement);
}

fn hint_description(mutation: &Mutation) -> String {
    match *mutation {
        Mutation::SetBoundary(side) => format!("set_boundary({side:?})"),
        Mutation::SetValue(v) => format!("set_value({v})"),
        Mutation::FlipBit(b) => format!("flip_bit({b})"),
        Mutation::SetBits(m) => format!("set_bits({m})"),
        Mutation::ClearBits(m) => format!("clear_bits({m})"),
        Mutation::Inc(d) => format!("inc({d})"),
        Mutation::Dec(d) => format!("dec({d})"),
        Mutation::SampleRange(lo, hi) => format!("sample_range({lo}, {hi})"),
        Mutation::Keep => "keep".into(),
    }
}

/// Cross-rule merge: pick a secondary rule, add any nodes it requires that
/// are not already present, and satisfy its complete state (target state plus
/// at least one precondition when the list is non-empty) while the complete
/// primary rule (target state plus at least one precondition) remains
/// satisfied. On any conflict the merge is skipped atomically. The child
/// scenario accumulates the merged values and their recorded placements.
fn cross_merge<R: Rand>(
    rand: &mut R,
    primary: &Rule,
    input: &mut ScenarioInput,
    child: &mut SemanticScenario,
    rules: &[Rule],
) {
    let secondary_candidates: Vec<&Rule> = rules
        .iter()
        .filter(|r| r.name != primary.name && r.semantic.is_none())
        .collect();
    if secondary_candidates.is_empty() {
        return;
    }
    let idx = rand.below(unsafe { NonZeroUsize::new_unchecked(secondary_candidates.len()) });
    let secondary = secondary_candidates[idx];

    let mut trial_input = input.clone();
    let mut trial = child.clone();

    // Add any secondary nodes that are missing from the skeleton.
    for node in &secondary.nodes {
        if trial.values.contains_key(&node.name) {
            continue;
        }
        let value = random_value_for_node(node, rand);
        record_placement(&mut trial, node, rand);
        let placement = match trial.placements.get(&node.name).copied() {
            Some(placement) => placement,
            None => return,
        };
        if place_node_value(&mut trial_input, node, &value, placement, rand).is_err() {
            return;
        }
        trial.values.insert(node.name.clone(), value);
        trial.nodes.insert(node.name.clone(), node.clone());
    }

    // Satisfy at least one secondary precondition when the list is
    // non-empty. Skip conditions on the primary target variable to avoid
    // overwriting the primary target into contradiction.
    if !secondary.preconditions.is_empty() {
        let mut conds: Vec<&Condition> = secondary.preconditions.iter().collect();
        conds.sort_by(|a, b| canonical_edge_id(a).cmp(&canonical_edge_id(b)));
        conds.retain(|c| c.predicate_var() != primary.target_var());
        let mut satisfied = false;
        for cond in conds {
            let node = match secondary.node_for(cond.predicate_var()) {
                Some(n) => n,
                None => continue,
            };
            let placement = trial.placements.get(node.name.as_str()).copied();
            let current = placement.and_then(|p| read_node_value(&trial_input, node, p));
            let value = match generate_satisfying(&cond.predicate, node, current, rand) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let placement = match trial.placements.get(node.name.as_str()).copied() {
                Some(p) => p,
                None => continue,
            };
            if set_node_value(&mut trial_input, node, &value, placement).is_err() {
                continue;
            }
            trial.values.insert(node.name.clone(), value);
            satisfied = true;
            break;
        }
        if !satisfied {
            return;
        }
    }

    // Satisfy the complete secondary target state by executing the
    // secondary rule's mutation hint.
    let secondary_target = match secondary.node_for(secondary.target_var()) {
        Some(n) => n,
        None => return,
    };
    {
        let placement = trial.placements.get(secondary.target_var()).copied();
        let current = placement.and_then(|p| read_node_value(&trial_input, secondary_target, p));
        let value = match apply_mutation_hint(
            &secondary.trigger.predicate,
            secondary_target,
            &secondary.mutation,
            current,
            rand,
        ) {
            Ok(v) => v,
            Err(_) => return,
        };
        let placement = match trial.placements.get(secondary.target_var()).copied() {
            Some(p) => p,
            None => return,
        };
        if set_node_value(&mut trial_input, secondary_target, &value, placement).is_err() {
            return;
        }
        trial.values.insert(secondary.target_var().to_string(), value);
    }

    // The complete combined state must hold: primary target state, primary
    // preconditions, secondary target state, and secondary preconditions.
    if !rule_state_satisfied(&trial_input, primary, child) {
        return;
    }
    if !rule_state_satisfied(&trial_input, secondary, &trial) {
        return;
    }

    *input = trial_input;
    *child = trial;
}

/// Whether a rule's target state and at-least-one precondition hold for the
/// values readable from `input` at their stored placements. Returns false
/// when a needed placement or value cannot be resolved.
fn rule_state_satisfied(input: &ScenarioInput, rule: &Rule, placements: &SemanticScenario) -> bool {
    let target_node = match rule.node_for(rule.target_var()) {
        Some(n) => n,
        None => return false,
    };
    let target = placements
        .placements
        .get(rule.target_var())
        .copied()
        .and_then(|placement| read_node_value(input, target_node, placement));
    let target = match target {
        Some(v) => v,
        None => return false,
    };
    if !rule.trigger.predicate.satisfied_by(target, target_node.width_bits) {
        return false;
    }
    if rule.preconditions.is_empty() {
        return true;
    }
    rule.preconditions.iter().any(|c| {
        match rule.node_for(c.predicate_var()) {
            Some(n) => {
                placements
                    .placements
                    .get(c.predicate_var())
                    .copied()
                    .and_then(|placement| read_node_value(input, n, placement))
                    .is_some_and(|v| c.predicate.satisfied_by(v, n.width_bits))
            }
            None => false,
        }
    })
}

/// Apply a mutator operator to the current value. Out-of-domain values are
/// rejected rather than clamped or truncated. Signed ranges sample under the
/// predicate's signedness.
fn apply_mutation<R: Rand>(current: u64, node: &Node, predicate: &Predicate, mutation: &Mutation, rand: &mut R) -> Result<Value, String> {
    let max = node.max_value();
    let value = match *mutation {
        Mutation::SetBoundary(BoundarySide::Above) => {
            let delta = 1 + rand.below(unsafe { NonZeroUsize::new_unchecked(4) }) as u64;
            current.checked_add(delta).filter(|v| *v <= max)
                .ok_or("SetBoundary Above unreachable")?
        }
        Mutation::SetBoundary(BoundarySide::Below) => {
            let delta = 1 + rand.below(unsafe { NonZeroUsize::new_unchecked(4) }) as u64;
            current.checked_sub(delta).ok_or("SetBoundary Below unreachable")?
        }
        Mutation::SetBoundary(BoundarySide::Min) => 0,
        Mutation::SetBoundary(BoundarySide::Max) => max,
        Mutation::SetValue(v) => {
            if v > max { return Err(format!("SetValue {v} out of width {} domain", node.width_bits)); }
            v
        }
        Mutation::FlipBit(b) => {
            if b >= node.width_bits { return Err(format!("bit {b} out of width {}", node.width_bits)); }
            current ^ (1u64 << b)
        }
        Mutation::SetBits(m) => {
            let v = current | m;
            if v > max { return Err(format!("SetBits result {v} out of width {} domain", node.width_bits)); }
            v
        }
        Mutation::ClearBits(m) => current & !m,
        Mutation::Inc(d) => current.checked_add(d).filter(|v| *v <= max).ok_or("Inc overflow")?,
        Mutation::Dec(d) => current.checked_sub(d).ok_or("Dec underflow")?,
        Mutation::SampleRange(lo, hi) => {
            if predicate.signedness() == Signedness::Signed {
                sample_range_signed(lo, hi, node, rand)?
            } else {
                sample_range(lo, hi, node, rand)?
            }
        }
        Mutation::Keep => current,
    };
    let value = Value::from_u64(value, node.width_bits)?;
    // One uniform target-predicate validation: a mutation that does not
    // satisfy the target state is rejected, never returned as Ok.
    if !predicate.satisfied_by(value.as_u64().unwrap_or(0), node.width_bits) {
        return Err(format!(
            "mutation result does not satisfy the target predicate"
        ));
    }
    Ok(value)
}

/// Inclusive uniform sample inside [lo, hi] under the node's width, rejecting
/// empty ranges and out-of-domain endpoints without saturating arithmetic.
fn sample_range<R: Rand>(lo: u64, hi: u64, node: &Node, rand: &mut R) -> Result<u64, String> {
    let max = node.max_value();
    if lo > max || hi > max {
        return Err(format!("range endpoint out of width {} domain", node.width_bits));
    }
    if lo > hi {
        return Err("empty range".into());
    }
    let range = (hi as u128) - (lo as u128) + 1;
    let offset = uniform_below(range, rand);
    Ok(lo + offset as u64)
}

/// Inclusive uniform sample inside [lo, hi] for signed two-complement
/// encoded endpoints.
fn sample_range_signed<R: Rand>(lo: u64, hi: u64, node: &Node, rand: &mut R) -> Result<u64, String> {
    let width = node.width_bits;
    let lo_s = signed_value(lo, width, Signedness::Signed);
    let hi_s = signed_value(hi, width, Signedness::Signed);
    if lo_s > hi_s {
        return Err("empty signed range".into());
    }
    let min_s = min_signed_for_width(width);
    let max_s = max_signed_for_width(width);
    if lo_s < min_s || hi_s > max_s {
        return Err(format!("range endpoint out of width {} signed domain", width));
    }
    let range = (hi_s - lo_s + 1) as u128;
    let offset = uniform_below(range, rand);
    let sampled = lo_s + offset as i128;
    Ok(encode_signed(sampled, width))
}

/// Uniform sample in [0, range). `range` may cover the full u64 domain.
fn uniform_below<R: Rand>(range: u128, rand: &mut R) -> u128 {
    if range == 0 {
        return 0;
    }
    if range > u64::MAX as u128 {
        return random_u64(rand) as u128;
    }
    rand.below(unsafe { NonZeroUsize::new_unchecked(range as usize) }) as u128
}

/// Re-encode a signed value in the node width as a two-complement pattern.
fn encode_signed(value: i128, width_bits: u8) -> u64 {
    let max = max_for_width(width_bits);
    (value as u64) & max
}

/// Interpret a value according to the declared signedness for comparisons.
fn signed_value(value: u64, width_bits: u8, signedness: Signedness) -> i128 {
    if signedness != Signedness::Signed {
        return value as i128;
    }
    if width_bits == 0 || width_bits > 64 {
        return value as i128;
    }
    if width_bits == 64 {
        // Sign-extend the full 64-bit pattern.
        return value as i64 as i128;
    }
    let mask = (1u64 << width_bits) - 1;
    let sign_bit = 1u64 << (width_bits - 1);
    let v = value & mask;
    if v & sign_bit != 0 {
        (v as i128) - (1i128 << width_bits)
    } else {
        v as i128
    }
}

/// Nearest value strictly above `threshold` under the predicate's signedness.
fn nearest_above(node: &Node, threshold: u64, signedness: Signedness) -> Result<Option<u64>, String> {
    let max = node.max_value();
    if threshold > max {
        return Err(format!("threshold {threshold} out of width {} domain", node.width_bits));
    }
    let candidate = if signedness == Signedness::Signed {
        let signed = signed_value(threshold, node.width_bits, signedness);
        if signed >= max_signed_for_width(node.width_bits) {
            return Ok(None);
        }
        encode_signed(signed + 1, node.width_bits)
    } else {
        if threshold >= max {
            return Ok(None);
        }
        threshold + 1
    };
    // Verify the candidate truly is above the threshold under the predicate
    // semantics.
    if !Predicate::Gt(threshold, signedness).satisfied_by(candidate, node.width_bits) {
        return Ok(None);
    }
    Ok(Some(candidate))
}

/// Nearest value strictly below `threshold` under the predicate's signedness.
fn nearest_below(node: &Node, threshold: u64, signedness: Signedness) -> Result<Option<u64>, String> {
    let max = node.max_value();
    if threshold > max {
        return Err(format!("threshold {threshold} out of width {} domain", node.width_bits));
    }
    let candidate = if signedness == Signedness::Signed {
        let signed = signed_value(threshold, node.width_bits, signedness);
        if signed <= min_signed_for_width(node.width_bits) {
            return Ok(None);
        }
        encode_signed(signed - 1, node.width_bits)
    } else {
        if threshold == 0 {
            return Ok(None);
        }
        threshold - 1
    };
    if !Predicate::Lt(threshold, signedness).satisfied_by(candidate, node.width_bits) {
        return Ok(None);
    }
    Ok(Some(candidate))
}

/// Boundary candidate values above the threshold. For unsigned integers of
/// width w this is {C+1, C+2, 2^(w-1), 2^w-1}; equality is included when the
/// predicate allows it (Ge).
fn candidates_above(node: &Node, threshold: u64, signedness: Signedness, include_equal: bool) -> Result<Vec<u64>, String> {
    let mut candidates = Vec::new();
    if include_equal {
        candidates.push(threshold);
    }
    for delta in 1..=2u64 {
        if signedness == Signedness::Signed {
            let signed = signed_value(threshold, node.width_bits, signedness);
            let candidate = signed + delta as i128;
            if candidate <= max_signed_for_width(node.width_bits) {
                candidates.push(encode_signed(candidate, node.width_bits));
            }
        } else {
            if let Some(candidate) = threshold.checked_add(delta) {
                if candidate <= node.max_value() {
                    candidates.push(candidate);
                }
            }
        }
    }
    if signedness == Signedness::Signed {
        candidates.push(encode_signed(max_signed_for_width(node.width_bits), node.width_bits));
    } else {
        let half = 1u64 << (node.width_bits - 1);
        candidates.push(half);
        candidates.push(node.max_value());
    }
    Ok(candidates)
}

/// Boundary candidate values below the threshold: {C-1, C-2, floor}.
/// Equality is included when the predicate allows it (Le).
fn candidates_below(node: &Node, threshold: u64, signedness: Signedness, include_equal: bool) -> Result<Vec<u64>, String> {
    let mut candidates = Vec::new();
    if include_equal {
        candidates.push(threshold);
    }
    for delta in 1..=2u64 {
        if signedness == Signedness::Signed {
            let signed = signed_value(threshold, node.width_bits, signedness);
            let candidate = signed - delta as i128;
            if candidate >= min_signed_for_width(node.width_bits) {
                candidates.push(encode_signed(candidate, node.width_bits));
            }
        } else {
            if let Some(candidate) = threshold.checked_sub(delta) {
                candidates.push(candidate);
            }
        }
    }
    if signedness == Signedness::Signed {
        candidates.push(encode_signed(min_signed_for_width(node.width_bits), node.width_bits));
    } else {
        candidates.push(0);
    }
    Ok(candidates)
}

/// Generate a value that satisfies a predicate, rejecting out-of-domain
/// targets. `current` is preserved as the base when present.
fn generate_satisfying<R: Rand>(predicate: &Predicate, node: &Node, current: Option<u64>, rand: &mut R) -> Result<Value, String> {
    let max = node.max_value();
    let value = match *predicate {
        Predicate::BitSet(b) => {
            if b >= node.width_bits as u32 {
                return Err(format!("bit {} out of width {}", b, node.width_bits));
            }
            let base = current.unwrap_or_else(|| random_u64(rand) & max);
            base | (1u64 << b)
        }
        Predicate::BitClear(b) => {
            if b >= node.width_bits as u32 {
                return Err(format!("bit {} out of width {}", b, node.width_bits));
            }
            let base = current.unwrap_or_else(|| random_u64(rand) & max);
            base & !(1u64 << b)
        }
        Predicate::Eq(v) => {
            if v > max { return Err(format!("Eq value {v} out of width {} domain", node.width_bits)); }
            v
        }
        Predicate::Ne(v) => {
            if max == 0 { return Err("no value satisfies Ne under zero width".into()); }
            if let Some(existing) = current {
                if existing != v && existing <= max {
                    return Value::from_u64(existing, node.width_bits);
                }
            }
            loop {
                let candidate = random_u64(rand) & max;
                if candidate != v { break candidate; }
            }
        }
        Predicate::Lt(v, s) => nearest_below(node, v, s)?.ok_or("Lt target unreachable")?,
        Predicate::Gt(v, s) => nearest_above(node, v, s)?.ok_or("Gt target unreachable")?,
        // Equality is allowed: Ge(C) and Le(C) are satisfied by C itself,
        // including Ge(MAX) and Le(MIN).
        Predicate::Le(v, _) => v,
        Predicate::Ge(v, _) => v,
        Predicate::InRange(lo, hi, s) => {
            if !Predicate::InRange(lo, hi, s).in_domain(node.width_bits) {
                return Err(format!("InRange [{lo}, {hi}] out of width {} domain", node.width_bits));
            }
            if s == Signedness::Signed {
                sample_range_signed(lo, hi, node, rand)?
            } else {
                sample_range(lo, hi, node, rand)?
            }
        }
    };
    Value::from_u64(value, node.width_bits)
}

/// Execute the rule's mutation hint on the base value and move the target
/// variable toward the target predicate. Boundary hints pick candidates just
/// across the predicate threshold; every other hint executes its requested
/// operator directly. The caller revalidates the target predicate and
/// rejects rules whose hint cannot reach the target state.
fn apply_mutation_hint<R: Rand>(predicate: &Predicate, node: &Node, mutation: &Mutation, current: Option<u64>, rand: &mut R) -> Result<Value, String> {
    let max = node.max_value();
    let base = current.unwrap_or_else(|| random_u64(rand) & max);
    let value = match *mutation {
        Mutation::SetBoundary(BoundarySide::Above) => {
            let threshold = predicate.threshold().ok_or("SetBoundary Above requires a scalar predicate threshold")?;
            let signedness = predicate.signedness();
            let candidates = candidates_above(node, threshold, signedness, false)?;
            pick_candidate(&candidates, predicate, node, rand).ok_or("SetBoundary Above unreachable")?
        }
        Mutation::SetBoundary(BoundarySide::Below) => {
            let threshold = predicate.threshold().ok_or("SetBoundary Below requires a scalar predicate threshold")?;
            let signedness = predicate.signedness();
            let candidates = candidates_below(node, threshold, signedness, false)?;
            pick_candidate(&candidates, predicate, node, rand).ok_or("SetBoundary Below unreachable")?
        }
        Mutation::SetBoundary(BoundarySide::Min) => 0,
        Mutation::SetBoundary(BoundarySide::Max) => max,
        Mutation::SetValue(v) => {
            if v > max { return Err(format!("SetValue {v} out of width {} domain", node.width_bits)); }
            v
        }
        Mutation::FlipBit(b) => {
            if b >= node.width_bits { return Err(format!("bit {b} out of width {}", node.width_bits)); }
            base ^ (1u64 << b)
        }
        Mutation::SetBits(m) => {
            let v = base | m;
            if v > max { return Err(format!("SetBits result {v} out of width {} domain", node.width_bits)); }
            v
        }
        Mutation::ClearBits(m) => base & !m,
        Mutation::Inc(d) => base.checked_add(d).filter(|v| *v <= max).ok_or("Inc overflow")?,
        Mutation::Dec(d) => base.checked_sub(d).ok_or("Dec underflow")?,
        Mutation::SampleRange(lo, hi) => {
            if predicate.signedness() == Signedness::Signed {
                sample_range_signed(lo, hi, node, rand)?
            } else {
                sample_range(lo, hi, node, rand)?
            }
        }
        Mutation::Keep => base,
    };
    let value = Value::from_u64(value, node.width_bits)?;
    // One uniform target-predicate validation: a hint that does not reach
    // the target state is an explicit rejection, never a substituted value.
    if !predicate.satisfied_by(value.as_u64().unwrap_or(0), node.width_bits) {
        return Err(format!(
            "mutation hint does not reach the target predicate"
        ));
    }
    Ok(value)
}

/// Pick a candidate that satisfies the predicate; otherwise None.
fn pick_candidate<R: Rand>(candidates: &[u64], predicate: &Predicate, node: &Node, rand: &mut R) -> Option<u64> {
    let survivors: Vec<u64> = candidates.iter().copied()
        .filter(|v| predicate.satisfied_by(*v, node.width_bits))
        .collect();
    if survivors.is_empty() {
        return None;
    }
    Some(survivors[rand.below(unsafe { NonZeroUsize::new_unchecked(survivors.len()) })])
}

/// Read the current numeric value of a node from the wire input at its
/// exact stored placement. The placement's region selects the specific
/// coherent allocation or streaming unit and its visit selects the word
/// visit; there is no region scan or last-visit fallback.
fn read_node_value(input: &ScenarioInput, node: &Node, placement: Placement) -> Option<u64> {
    let (offset, size) = match node.source {
        Source::Mmio { offset, size } => (offset, size),
        Source::Coherent { offset, size } => {
            // The placement's region ordinal selects the exact allocation.
            return input
                .dma
                .coherent
                .iter()
                .find(|a| a.addr == placement.region as u64)
                .and_then(|a| read_bytes_at(&a.word_models, offset, size, placement.visit));
        }
        Source::Streaming { offset, size, .. } => {
            // The placement's region ordinal selects the exact streaming unit.
            return input
                .dma
                .streaming
                .iter()
                .find(|u| u.addr == placement.region as u64)
                .and_then(|u| read_bytes_at(&u.word_models, offset, size, placement.visit));
        }
    };
    read_bytes_at(&input.mmio.word_models, offset, size, placement.visit)
}

/// Read `size` bytes starting at `offset` from the stored visit of
/// visit-ordered word models. Returns None when the containing model or the
/// stored visit is missing.
fn read_bytes_at(models: &[WordModel], offset: u32, size: u8, visit: usize) -> Option<u64> {
    let mut value = 0u64;
    for index in 0..size {
        let address = offset.checked_add(index as u32)?;
        let aligned = address & !3;
        let model = models.iter().find(|m| m.offset == aligned)?;
        if visit >= model.values.len() {
            return None;
        }
        let word = model.values[visit];
        let byte = (word >> ((address & 3) * 8)) & 0xff;
        value |= (byte as u64) << (8 * index);
    }
    Some(value)
}

/// Lift a wire-format input back to a semantic scenario for one rule using
/// the stored placement map. A field without a stored placement cannot be
/// lifted: the wire layout does not encode placement, so this returns None
/// instead of guessing a region or visit.
#[must_use]
pub fn lift_with(
    input: &ScenarioInput,
    rule: &Rule,
    placements: &alloc::collections::BTreeMap<String, Placement>,
) -> Option<SemanticScenario> {
    let mut scenario = SemanticScenario {
        target_rule: rule.name.clone(),
        values: alloc::collections::BTreeMap::new(),
        nodes: alloc::collections::BTreeMap::new(),
        placements: alloc::collections::BTreeMap::new(),
        slot_regions: alloc::collections::BTreeMap::new(),
    };
    for node in &rule.nodes {
        let placement = placements.get(&node.name).copied()?;
        let value = if rule.semantic.is_some() { semantic::read_value(rule, input, node, placement)? }
                    else { read_node_value(input, node, placement)? };
        let value = Value::from_u64(value, node.width_bits).ok()?;
        scenario.values.insert(node.name.clone(), value);
        scenario.nodes.insert(node.name.clone(), node.clone());
        scenario.insert_placement(&node.name, placement);
    }
    Some(scenario)
}

/// Recover a field's runtime placement from the wire and the rule's own
/// field set.
///
/// The encoding gives a physical word group one fill-read count and
/// consecutive visits in canonical node order, so
/// base = word value length - group size and visit = base + rank. Streaming
/// buffers fill once, so their visit is 0. The region is the scanned unit
/// holding the field's word; the target-predicate revalidation guards
/// foreign inputs where the scan is ambiguous.
/// Update a node's value in place at its exact stored placement, preserving
/// the modelled skeleton: the field bytes change inside the existing model
/// and visit, and no model or visit is added.
fn set_node_value(input: &mut ScenarioInput, node: &Node, value: &Value, placement: Placement) -> Result<(), String> {
    match node.source {
        Source::Mmio { offset, .. } => update_in_models(&mut input.mmio.word_models, offset, node, value, placement.visit),
        Source::Coherent { offset, .. } => {
            // The placement's region ordinal selects the exact allocation.
            let alloc = input
                .dma
                .coherent
                .iter_mut()
                .find(|a| a.addr == placement.region as u64)
                .ok_or("no modelled placement for coherent node")?;
            update_in_models(&mut alloc.word_models, offset, node, value, placement.visit)
        }
        Source::Streaming { offset, .. } => {
            // The placement's region ordinal selects the exact streaming unit.
            let unit = input
                .dma
                .streaming
                .iter_mut()
                .find(|u| u.addr == placement.region as u64)
                .ok_or("no modelled placement for streaming node")?;
            update_in_models(&mut unit.word_models, offset, node, value, placement.visit)
        }
    }
}

/// Place a node's value at its exact recorded placement, creating the model
/// and visit when missing. Used for generation-time placement of new nodes.
fn place_node_value<R: Rand>(input: &mut ScenarioInput, node: &Node, value: &Value, placement: Placement, rand: &mut R) -> Result<(), String> {
    let bytes = value_bytes(value, node)?;
    match node.source {
        Source::Mmio { offset, .. } => {
            write_bytes_at(&mut input.mmio.word_models, offset, &bytes, placement.visit, rand);
            Ok(())
        }
        Source::Coherent { offset, .. } => {
            let region = placement.region;
            while input.dma.coherent.len() <= region as usize {
                input.dma.coherent.push(CoherentAlloc { addr: input.dma.coherent.len() as u64, word_models: Vec::new() });
            }
            write_bytes_at(&mut input.dma.coherent[region as usize].word_models, offset, &bytes, placement.visit, rand);
            Ok(())
        }
        Source::Streaming { offset, .. } => {
            // The placement's region selects the runtime mapping ordinal;
            // the protocol slot is never compared to StreamUnit.addr.
            let region = placement.region;
            if let Some(unit) = input.dma.streaming.iter_mut().find(|u| u.addr == region as u64) {
                write_bytes_at(&mut unit.word_models, offset, &bytes, placement.visit, rand);
                return Ok(());
            }
            let mut unit = StreamUnit { addr: region as u64, word_models: Vec::new() };
            write_bytes_at(&mut unit.word_models, offset, &bytes, placement.visit, rand);
            input.dma.streaming.push(unit);
            Ok(())
        }
    }
}

/// Serialize a value to its little-endian byte payload, enforcing the node's
/// declared width. Byte payloads outside the node width are rejected rather
/// than truncated.
fn value_bytes(value: &Value, node: &Node) -> Result<Vec<u8>, String> {
    let size = node.size_bytes() as usize;
    if size == 0 || size > 8 {
        return Err(format!("invalid node access width {size}"));
    }
    match *value {
        Value::U8(v) => Ok(vec![v]),
        Value::U16(v) => Ok(v.to_le_bytes().to_vec()),
        Value::U32(v) => Ok(v.to_le_bytes().to_vec()),
        Value::U64(v) => Ok(v.to_le_bytes().to_vec()),
        Value::Bytes(ref bytes) => {
            if bytes.is_empty() {
                return Err("empty byte payload".into());
            }
            if bytes.len() > size {
                return Err(format!(
                    "byte payload of {} bytes exceeds node width {} bytes",
                    bytes.len(), size
                ));
            }
            Ok(bytes.clone())
        }
    }
}

/// Merge one byte into the exact stored visit of the field; the model must
/// already exist and the visit must be present.
fn update_byte_in_models_at(models: &mut Vec<WordModel>, address: u32, byte: u8, visit: usize) -> Result<(), String> {
    let aligned = address & !3;
    let model = models.iter_mut().find(|m| m.offset == aligned)
        .ok_or_else(|| format!("no modelled placement for word 0x{aligned:x}"))?;
    if visit >= model.values.len() {
        return Err(format!("stored visit {visit} is missing from word 0x{aligned:x}"));
    }
    let shift = (address & 3) * 8;
    let mask = 0xffu32 << shift;
    let word = model.values[visit];
    model.values[visit] = (word & !mask) | (((byte as u32) << shift) & mask);
    Ok(())
}

/// Update a field's bytes in its stored visit without creating models or
/// visits.
fn update_in_models(models: &mut Vec<WordModel>, offset: u32, node: &Node, value: &Value, visit: usize) -> Result<(), String> {
    let bytes = value_bytes(value, node)?;
    for (index, byte) in bytes.iter().enumerate() {
        let address = offset.checked_add(index as u32).ok_or("field offset overflow")?;
        update_byte_in_models_at(models, address, *byte, visit)?;
    }
    Ok(())
}

/// Merge the bytes of one field into visit-ordered word models, creating
/// models and visit slots as needed. All bytes of the field share one visit.
fn write_bytes_at<R: Rand>(models: &mut Vec<WordModel>, offset: u32, bytes: &[u8], visit: usize, rand: &mut R) {
    for (index, byte) in bytes.iter().enumerate() {
        let Some(address) = offset.checked_add(index as u32) else { break };
        let aligned = address & !3;
        if !models.iter().any(|m| m.offset == aligned) {
            models.push(WordModel { offset: aligned, values: Vec::new() });
        }
        let model = models.iter_mut().find(|m| m.offset == aligned).unwrap();
        while model.values.len() <= visit {
            model.values.push(random_u32(rand));
        }
        let shift = (address & 3) * 8;
        let mask = 0xffu32 << shift;
        let word = model.values[visit];
        model.values[visit] = (word & !mask) | (((*byte as u32) << shift) & mask);
    }
}

/// Lower a semantic scenario to the wire format.
///
/// Every semantic field is placed at its exact stored `Placement`: the
/// region selects the coherent allocation or streaming unit and the visit
/// selects the word visit. A field without a recorded placement draws one
/// independent random region and visit here, and the draw is recorded back
/// into the scenario so the metadata stays complete. Lowering never depends
/// on `HashMap` iteration order and never recovers placement from the wire.
pub fn lower_scenario<R: Rand>(scenario: &mut SemanticScenario, _rule: &Rule, rand: &mut R) -> Result<ScenarioInput, String> {
    if _rule.semantic.is_some() { return semantic::lower(_rule, scenario, rand); }
    let mut mmio = Vec::new();
    let mut coherent = Vec::new();
    let mut streaming = Vec::new();

    // Lower every value that has node metadata. Use canonical node id order;
    // never HashMap iteration order.
    let mut node_names: Vec<String> = scenario.values.keys().cloned().collect();
    node_names.sort_by_key(|name| {
        scenario.nodes.get(name).map(|n| n.canonical_id()).unwrap_or_else(|| name.clone())
    });

    // Fill in any missing placement once: each field independently draws a
    // random region and visit, recorded for exact later reuse.
    for name in &node_names {
        if scenario.placements.contains_key(name) {
            continue;
        }
        let node = scenario.nodes.get(name).cloned()
            .ok_or_else(|| format!("no node metadata for {name}"))?;
        record_placement(scenario, &node, rand);
    }

    // Streaming fields sharing one protocol slot model one buffer; each slot
    // group becomes its own streaming unit at its recorded runtime region.
    let mut slot_groups: alloc::collections::BTreeMap<u8, Vec<&String>> = Default::default();
    for name in &node_names {
        if let Some(node) = scenario.nodes.get(name) {
            if let Source::Streaming { slot, .. } = node.source {
                slot_groups.entry(slot).or_default().push(name);
            }
        }
    }

    for name in &node_names {
        let node = scenario.nodes.get(name).ok_or_else(|| format!("no node metadata for {name}"))?;
        let value = scenario.values.get(name).ok_or_else(|| format!("no value for {name}"))?;
        let placement = scenario
            .placements
            .get(name)
            .copied()
            .ok_or_else(|| format!("no placement for {name}"))?;
        let bytes = value_bytes(value, node)?;
        match node.source {
            Source::Mmio { offset, .. } => {
                write_bytes_at(&mut mmio, offset, &bytes, placement.visit, rand);
            }
            Source::Coherent { offset, .. } => {
                let region = placement.region;
                while coherent.len() <= region as usize {
                    coherent.push(CoherentAlloc { addr: coherent.len() as u64, word_models: Vec::new() });
                }
                write_bytes_at(&mut coherent[region as usize].word_models, offset, &bytes, placement.visit, rand);
            }
            Source::Streaming { .. } => {}
        }
    }

    for (slot, names) in slot_groups {
        // The runtime region for a slot group is drawn once and recorded;
        // a scenario with partial metadata gets a fresh draw here.
        let region = match scenario.slot_regions.get(&slot).copied() {
            Some(region) => region,
            None => {
                let used: Vec<u8> = scenario.slot_regions.values().copied().collect();
                let region = random_region_excluding(&used, rand);
                scenario.slot_regions.insert(slot, region);
                region
            }
        };
        let mut unit = StreamUnit { addr: region as u64, word_models: Vec::new() };
        for name in names {
            let node = scenario.nodes.get(name).ok_or_else(|| format!("no node metadata for {name}"))?;
            let value = scenario.values.get(name).ok_or_else(|| format!("no value for {name}"))?;
            let visit = scenario
                .placements
                .get(name)
                .map(|p| p.visit)
                .unwrap_or(0);
            let bytes = value_bytes(value, node)?;
            let offset = match node.source {
                Source::Streaming { offset, .. } => offset,
                _ => continue,
            };
            write_bytes_at(&mut unit.word_models, offset, &bytes, visit, rand);
        }
        streaming.push(unit);
    }

    mmio.sort_by_key(|m| m.offset);
    coherent.sort_by_key(|a| a.addr);
    streaming.sort_by_key(|u| u.addr);
    for a in &mut coherent { a.word_models.sort_by_key(|m| m.offset); }
    for u in &mut streaming { u.word_models.sort_by_key(|m| m.offset); }
    Ok(ScenarioInput::new(MmioSection { word_models: mmio }, DmaSection { coherent, streaming }))
}

/// Draw a runtime region ordinal that no other protocol slot's group already
/// maps to. Deterministic for a fixed RNG.
fn random_region_excluding<R: Rand>(used: &[u8], rand: &mut R) -> u8 {
    for _ in 0..8 {
        let candidate = rand.below(unsafe { NonZeroUsize::new_unchecked(16) }) as u8;
        if !used.contains(&candidate) {
            return candidate;
        }
    }
    used.len() as u8
}

fn random_value_for_node<R: Rand>(node: &Node, rand: &mut R) -> Value {
    Value::from_u64(random_u64(rand) & node.max_value(), node.width_bits).expect("masked random value fits node width")
}

fn random_u64<R: Rand>(rand: &mut R) -> u64 {
    ((rand.below(unsafe { NonZeroUsize::new_unchecked(65536) }) as u64) << 48)
        | ((rand.below(unsafe { NonZeroUsize::new_unchecked(65536) }) as u64) << 32)
        | ((rand.below(unsafe { NonZeroUsize::new_unchecked(65536) }) as u64) << 16)
        | (rand.below(unsafe { NonZeroUsize::new_unchecked(65536) }) as u64)
}

fn choose_rule<'a, R: Rand>(rules: &'a [Rule], rand: &mut R) -> Result<&'a Rule, String> {
    let available: Vec<&Rule> = rules.iter().filter(|r| r.semantic.as_ref()
        .is_none_or(|s| s.blockers.is_empty())).collect();
    if available.is_empty() { return Err("no executable rules: inspect runtime_blockers()".into()); }
    Ok(available[rand.below(unsafe { NonZeroUsize::new_unchecked(available.len()) })])
}

fn sorted_preconditions(rule: &Rule) -> Vec<&Condition> {
    let mut v: Vec<_> = rule.preconditions.iter().collect();
    v.sort_by(|a, b| canonical_edge_id(a).cmp(&canonical_edge_id(b)));
    v
}

fn canonical_rule_id(rule: &Rule) -> String {
    rule.name.clone()
}

/// Validate the canonical rule id against the rule fields. The id is
/// preserved verbatim; the target node and predicate text are recomputed and
/// must match exactly, otherwise this is an identity conflict.
fn validate_canonical_rule_id(rule: &Rule) -> Result<(), String> {
    let name = &rule.name;
    let rest = name.strip_prefix("rule:").ok_or_else(|| format!("rule id {} has no rule: prefix", name))?;
    let (function, rest) = rest.split_once("|target:").ok_or_else(|| format!("rule id {name} has no target field"))?;
    let (target, predicate) = rest.split_once("|predicate:").ok_or_else(|| format!("rule id {name} has no predicate field"))?;
    let _ = function;
    if target != rule.trigger.dst {
        return Err(format!(
            "rule id conflict: {} targets {} but the trigger targets {}",
            name, target, rule.trigger.dst
        ));
    }
    let expected = predicate_text(&rule.trigger.predicate);
    if predicate != expected {
        return Err(format!(
            "rule id conflict: {} carries predicate {} but the trigger serializes to {}",
            name, predicate, expected
        ));
    }
    Ok(())
}

fn canonical_edge_id(cond: &Condition) -> String {
    format!("{}|{}|{}|{}", cond.src, cond.dst, cond.head.as_str(), predicate_text(&cond.predicate))
}

fn predicate_text(pred: &Predicate) -> String {
    match *pred {
        Predicate::BitSet(b) => format!("bit_set:{b}"),
        Predicate::BitClear(b) => format!("bit_clear:{b}"),
        Predicate::Eq(v) => format!("eq:{v}"),
        Predicate::Ne(v) => format!("ne:{v}"),
        Predicate::Lt(v, Signedness::Signed) => format!("lt:signed:{v}"),
        Predicate::Lt(v, _) => format!("lt:unsigned:{v}"),
        Predicate::Gt(v, Signedness::Signed) => format!("gt:signed:{v}"),
        Predicate::Gt(v, _) => format!("gt:unsigned:{v}"),
        Predicate::Le(v, Signedness::Signed) => format!("le:signed:{v}"),
        Predicate::Le(v, _) => format!("le:unsigned:{v}"),
        Predicate::Ge(v, Signedness::Signed) => format!("ge:signed:{v}"),
        Predicate::Ge(v, _) => format!("ge:unsigned:{v}"),
        Predicate::InRange(lo, hi, Signedness::Signed) => format!("in_range:signed:{lo}:{hi}"),
        Predicate::InRange(lo, hi, _) => format!("in_range:unsigned:{lo}:{hi}"),
    }
}

fn encode_scenarios_equal(a: &ScenarioInput, b: &ScenarioInput) -> bool {
    crate::encoding::encode_scenario(a) == crate::encoding::encode_scenario(b)
}

fn random_u32<R: Rand>(rand: &mut R) -> u32 {
    ((rand.below(unsafe { NonZeroUsize::new_unchecked(65536) }) as u32) << 16) | rand.below(unsafe { NonZeroUsize::new_unchecked(65536) }) as u32
}

fn random_region<R: Rand>(rand: &mut R) -> u8 { rand.below(unsafe { NonZeroUsize::new_unchecked(4) }) as u8 }
fn random_visit<R: Rand>(rand: &mut R) -> usize { rand.below(unsafe { NonZeroUsize::new_unchecked(4) }) }

fn parse_u64(s: &str) -> Result<u64, String> {
    let (digits, radix) = s.strip_prefix("0x").map_or((s, 10), |v| (v, 16));
    u64::from_str_radix(digits, radix).map_err(|_| format!("invalid integer {s}"))
}

fn parse_u32(s: &str) -> Result<u32, String> {
    parse_u64(s).and_then(|v| u32::try_from(v).map_err(|_| format!("integer {s} does not fit u32")))
}

/// Parse the predicate tokens shared by trigger and precondition lines.
/// Relational predicates require an explicit signedness; unresolved or
/// missing signedness is rejected instead of silently choosing one.
fn parse_predicate_tokens(tokens: &[&str]) -> Result<Predicate, String> {
    let op = tokens.first().copied().ok_or("condition predicate missing")?;
    match op {
        "bit_set" => {
            let bit: u32 = tokens.get(1).ok_or("bit missing")?.parse().map_err(|_| "invalid bit".to_string())?;
            Ok(Predicate::BitSet(bit))
        }
        "bit_clear" => {
            let bit: u32 = tokens.get(1).ok_or("bit missing")?.parse().map_err(|_| "invalid bit".to_string())?;
            Ok(Predicate::BitClear(bit))
        }
        "eq" => Ok(Predicate::Eq(parse_u64(tokens.get(1).ok_or("value missing")?)?)),
        "ne" => Ok(Predicate::Ne(parse_u64(tokens.get(1).ok_or("value missing")?)?)),
        "lt" | "gt" | "le" | "ge" => {
            let signedness = match tokens.get(1).copied() {
                Some("signed") => Signedness::Signed,
                Some("unsigned") => Signedness::Unsigned,
                _ => return Err(format!("relational predicate {op} requires an explicit signedness")),
            };
            let value = parse_u64(tokens.get(2).ok_or("value missing")?)?;
            let predicate = match op {
                "lt" => Predicate::Lt(value, signedness),
                "gt" => Predicate::Gt(value, signedness),
                "le" => Predicate::Le(value, signedness),
                _ => Predicate::Ge(value, signedness),
            };
            Ok(predicate)
        }
        "in_range" => {
            let signedness = match tokens.get(1).copied() {
                Some("signed") => Signedness::Signed,
                Some("unsigned") => Signedness::Unsigned,
                _ => return Err("relational predicate in_range requires an explicit signedness".into()),
            };
            let lo = parse_u64(tokens.get(2).ok_or("range minimum missing")?)?;
            let hi = parse_u64(tokens.get(3).ok_or("range maximum missing")?)?;
            Ok(Predicate::InRange(lo, hi, signedness))
        }
        _ => Err(format!("unknown predicate {op}")),
    }
}

fn parse_rule(text: &str) -> Result<Rule, String> {
    if text.starts_with("sdg 1.2\n") { return semantic::parse(text); }
    let mut name = String::new();
    let mut nodes = Vec::new();
    let mut pre = Vec::new();
    let mut trigger = None;
    let mut mutation = Mutation::Keep;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let p: Vec<_> = line.split_whitespace().collect();
        match p.first().copied() {
            Some("rule") => name = p.get(1).ok_or("rule name missing")?.to_string(),
            Some("node") => {
                let node_name = p.get(1).ok_or("node name missing")?.to_string();
                let source = match *p.get(2).ok_or("node source missing")? {
                    "mmio" => {
                        let size: u8 = p.get(4).ok_or("mmio size missing")?.parse().map_err(|_| "invalid mmio size".to_string())?;
                        Source::Mmio {
                            offset: parse_u32(p.get(3).ok_or("mmio offset missing")?)?,
                            size,
                        }
                    }
                    "coherent" => {
                        let size: u8 = p.get(4).ok_or("coherent size missing")?.parse().map_err(|_| "invalid coherent size".to_string())?;
                        Source::Coherent {
                            offset: parse_u32(p.get(3).ok_or("coherent offset missing")?)?,
                            size,
                        }
                    }
                    "streaming" => {
                        let size: u8 = p.get(5).ok_or("streaming size missing")?.parse().map_err(|_| "invalid streaming size".to_string())?;
                        Source::Streaming {
                            slot: parse_u64(p.get(3).ok_or("streaming slot missing")?)? as u8,
                            offset: parse_u32(p.get(4).ok_or("streaming offset missing")?)?,
                            size,
                        }
                    }
                    source => return Err(format!("unknown source {source}")),
                };
                // Width in bits is derived from the access size in bytes;
                // zero or oversize widths are rejected cleanly.
                let size_bytes = source_size(&source);
                if size_bytes == 0 || size_bytes > 8 {
                    return Err(format!("invalid node access width {size_bytes}"));
                }
                let width_bits: u8 = size_bytes * 8;
                let node = Node { name: node_name, source, width_bits };
                // The node id must already be canonical: a mismatch is an
                // identity conflict.
                let canonical = node.canonical_id();
                if canonical != node.name {
                    return Err(format!(
                        "node identity conflict: {} serializes to {canonical}",
                        node.name
                    ));
                }
                nodes.push(node);
            }
            Some("precondition") => {
                if p.len() < 5 {
                    return Err("precondition line needs src, dst, head, and predicate".into());
                }
                let head = Head::from_str(p[3]).ok_or_else(|| format!("unknown head {}", p[3]))?;
                let predicate = parse_predicate_tokens(&p[4..])?;
                pre.push(Condition {
                    src: p[1].to_string(),
                    dst: p[2].to_string(),
                    head,
                    predicate,
                });
            }
            Some("trigger") => {
                if p.len() < 4 {
                    return Err("trigger line needs a node, head, and predicate".into());
                }
                let head = Head::from_str(p[2]).ok_or_else(|| format!("unknown head {}", p[2]))?;
                let predicate = parse_predicate_tokens(&p[3..])?;
                // Ne is guard-only and never a target state.
                if matches!(predicate, Predicate::Ne(_)) {
                    return Err("Ne cannot be used as a target state".into());
                }
                let node = p[1].to_string();
                trigger = Some(Condition { src: node.clone(), dst: node, head, predicate });
            }
            Some("mutation") => mutation = parse_mutation(&p[1..])?,
            _ => return Err(format!("unrecognized SDG line: {line}")),
        }
    }
    let trigger = trigger.ok_or("trigger missing")?;
    if !trigger.src.is_empty() && trigger.src != trigger.dst {
        return Err("trigger is not a self-edge".into());
    }
    let rule = Rule { name, nodes, preconditions: pre, trigger, mutation, semantic: None };
    validate_canonical_rule_id(&rule)?;
    Ok(rule)
}

/// Parse a rule from text for integration tests.
#[cfg(test)]
pub(crate) fn parse_rule_for_test(text: &str) -> Result<Rule, String> {
    parse_rule(text)
}

fn parse_mutation(p: &[&str]) -> Result<Mutation, String> {
    match p.first().copied().ok_or("mutation missing")? {
        "set_boundary" => {
            let side = match p.get(1).copied() {
                Some("above") => BoundarySide::Above,
                Some("below") => BoundarySide::Below,
                Some("min") => BoundarySide::Min,
                Some("max") => BoundarySide::Max,
                _ => return Err("set_boundary side missing".into()),
            };
            Ok(Mutation::SetBoundary(side))
        }
        "set_value" => Ok(Mutation::SetValue(parse_u64(p.get(1).ok_or("value missing")?)?)),
        "flip_bit" => Ok(Mutation::FlipBit(parse_u64(p.get(1).ok_or("bit missing")?)? as u8)),
        "set_bits" => Ok(Mutation::SetBits(parse_u64(p.get(1).ok_or("mask missing")?)?)),
        "clear_bits" => Ok(Mutation::ClearBits(parse_u64(p.get(1).ok_or("mask missing")?)?)),
        "inc" => Ok(Mutation::Inc(parse_u64(p.get(1).ok_or("delta missing")?)?)),
        "dec" => Ok(Mutation::Dec(parse_u64(p.get(1).ok_or("delta missing")?)?)),
        "sample_range" => Ok(Mutation::SampleRange(parse_u64(p.get(1).ok_or("minimum missing")?)?, parse_u64(p.get(2).ok_or("maximum missing")?)?)),
        "keep" => Ok(Mutation::Keep),
        x => Err(format!("unknown mutation {x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_edge_id, generate_satisfying, lower_scenario, max_signed_for_width,
        nearest_above, parse_rule, parse_predicate_tokens, signed_value, BoundarySide,
        Head, Mutation, Placement, Predicate, SemanticDependencyGraph, SemanticScenario,
        Signedness, Source, Value,
    };
    use crate::input::{MmioSection, ScenarioInput, WordModel};
    use libafl_bolts::rands::StdRand;

    fn make_rng(seed: u64) -> StdRand { StdRand::with_seed(seed) }

    fn word(offset: u32, values: &[u32]) -> WordModel {
        WordModel { offset, values: values.to_vec() }
    }

    #[test]
    fn parser_keeps_runtime_dma_placement_out_of_rules() {
        let rule = parse_rule(
            "rule rule:p|target:coherent:8:4:c|predicate:gt:unsigned:16\n\
             node coherent:8:4:c coherent 0x8 4\n\
             node streaming:0:4:2:s streaming 0 0x4 2\n\
             trigger coherent:8:4:c head_bound gt unsigned 16\n\
             mutation set_boundary above\n",
        )
        .unwrap();
        assert!(matches!(rule.nodes[0].source, Source::Coherent { offset: 8, size: 4 }));
        assert!(matches!(rule.nodes[1].source, Source::Streaming { slot: 0, offset: 4, size: 2 }));
    }

    #[test]
    fn parser_keeps_condition_src_dst_and_head() {
        let rule = parse_rule(
            "rule rule:p|target:mmio:266:2:mtu|predicate:gt:unsigned:40\n\
             node mmio:16:4:feat mmio 0x10 4\n\
             node mmio:266:2:mtu mmio 0x10a 2\n\
             precondition mmio:16:4:feat mmio:266:2:mtu head_guard bit_set 3\n\
             trigger mmio:266:2:mtu head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        )
        .unwrap();
        assert_eq!(rule.preconditions.len(), 1);
        let cond = &rule.preconditions[0];
        assert_eq!(cond.src, "mmio:16:4:feat");
        assert_eq!(cond.dst, "mmio:266:2:mtu");
        assert_eq!(cond.head, Head::Guard);
        assert_eq!(cond.predicate, Predicate::BitSet(3));
        // The predicate constrains the precondition source variable.
        assert_eq!(cond.predicate_var(), "mmio:16:4:feat");
        assert_eq!(canonical_edge_id(cond), "mmio:16:4:feat|mmio:266:2:mtu|head_guard|bit_set:3");
    }

    #[test]
    fn canonical_rule_id_is_preserved_and_validated() {
        // A rule id that disagrees with the trigger is an identity conflict.
        let rule = parse_rule(
            "rule rule:p|target:mmio:266:2:mtu|predicate:gt:unsigned:99\n\
             node mmio:266:2:mtu mmio 0x10a 2\n\
             trigger mmio:266:2:mtu head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        );
        assert!(rule.is_err(), "predicate mismatch must be an identity conflict");

        // A node id that disagrees with its source is an identity conflict.
        let rule = parse_rule(
            "rule rule:p|target:mmio:266:2:mtu|predicate:gt:unsigned:40\n\
             node mmio:266:2:mtu mmio 0x10b 2\n\
             trigger mmio:266:2:mtu head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        );
        assert!(rule.is_err(), "node id mismatch must be an identity conflict");
    }

    #[test]
    fn duplicate_rule_ids_are_identity_conflicts() {
        let dir = std::env::temp_dir().join(format!(
            "sdg-dup-rules-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let text = "rule rule:p|target:mmio:266:2:mtu|predicate:gt:unsigned:40\n\
                    node mmio:266:2:mtu mmio 0x10a 2\n\
                    trigger mmio:266:2:mtu head_bound gt unsigned 40\n\
                    mutation set_boundary above\n";
        std::fs::write(dir.join("a.sdg"), text).unwrap();
        std::fs::write(dir.join("b.sdg"), text).unwrap();
        let result = SemanticDependencyGraph::from_dir(&dir);
        assert!(result.is_err(), "duplicate canonical rule ids must conflict");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn text_rejects_unresolved_relational_signedness() {
        let rule = parse_rule(
            "rule rule:p|target:mmio:266:2:mtu|predicate:gt:unsigned:16\n\
             node mmio:266:2:mtu mmio 0x10a 2\n\
             trigger mmio:266:2:mtu head_bound gt 16\n\
             mutation set_boundary above\n",
        );
        assert!(rule.is_err(), "missing signedness must be rejected, not coerced");
    }

    #[test]
    fn unaligned_mmio_field_is_mask_merged() {
        let rule = parse_rule(
            "rule rule:p|target:mmio:273:1:x|predicate:eq:0\n\
             node mmio:273:1:x mmio 0x111 1\n\
             trigger mmio:273:1:x head_bound eq 0\n\
             mutation keep\n",
        ).unwrap();
        let mut models = vec![word(0x110, &[0xaabb_ccdd])];
        let value = Value::U8(0x42);
        let placement = Placement { region: 0, visit: 0 };
        super::update_in_models(&mut models, 0x111, &rule.nodes[0], &value, placement.visit).unwrap();
        assert_eq!(models[0].values[0], 0xaabb_42dd);
    }

    #[test]
    fn predicate_satisfaction_checks_signedness() {
        // 8-bit signed: 0xff == -1, so 0xff < 0 signed, but 0xff > 0 unsigned.
        let p = Predicate::Lt(0, Signedness::Signed);
        assert!(p.satisfied_by(0xff, 8));
        let p = Predicate::Lt(0, Signedness::Unsigned);
        assert!(!p.satisfied_by(0xff, 8));
    }

    #[test]
    fn signed_64_bit_values_are_sign_extended() {
        // The full 64-bit pattern 0xffff_ffff_ffff_ffff is -1 signed.
        assert_eq!(signed_value(u64::MAX, 64, Signedness::Signed), -1);
        assert_eq!(signed_value(0x8000_0000_0000_0000, 64, Signedness::Signed), i64::MIN as i128);
        assert_eq!(signed_value(0x7fff_ffff_ffff_ffff, 64, Signedness::Signed), i64::MAX as i128);
        // A signed comparison is satisfied by patterns with the sign bit
        // set: -1 < 0 signed but not unsigned.
        let p = Predicate::Lt(0, Signedness::Signed);
        assert!(p.satisfied_by(u64::MAX, 64));
        assert!(!p.satisfied_by(0, 64));
        let p = Predicate::Lt(0, Signedness::Unsigned);
        assert!(!p.satisfied_by(u64::MAX, 64));
    }

    #[test]
    fn signed_inrange_two_complement() {
        // 16-bit signed [-10, 10]: the minimum is the two-complement pattern
        // of -10 (0xfff6 = 65526) and the range is ordered under signedness.
        let p = Predicate::InRange(0xfff6, 0x000a, Signedness::Signed);
        assert!(p.in_domain(16));
        assert!(p.satisfied_by(0xfff6, 16)); // -10
        assert!(p.satisfied_by(10, 16));
        assert!(p.satisfied_by(0, 16));
        assert!(!p.satisfied_by(0xfff5, 16)); // -11
        assert!(!p.satisfied_by(11, 16));
        // The same patterns under unsigned ordering are an empty range.
        let p = Predicate::InRange(0xfff6, 0x000a, Signedness::Unsigned);
        assert!(!p.in_domain(16));
    }

    #[test]
    fn ge_and_le_generation_allows_equality_extrema() {
        // Ge(MAX) is satisfiable by MAX itself.
        let node = super::Node {
            name: "mmio:256:1:x".into(),
            source: Source::Mmio { offset: 0x100, size: 1 },
            width_bits: 8,
        };
        assert_eq!(nearest_above(&node, 255, Signedness::Unsigned).unwrap(), None,
                   "Gt(255) has no representable target");
        // Ge(255) is satisfied by 255 (equality allowed).
        let value = generate_satisfying(
            &Predicate::Ge(255, Signedness::Unsigned), &node, None, &mut make_rng(1),
        )
        .unwrap();
        assert_eq!(value, Value::U8(255));
        // Le(0) is satisfied by 0 (equality allowed).
        let value = generate_satisfying(
            &Predicate::Le(0, Signedness::Unsigned), &node, None, &mut make_rng(1),
        )
        .unwrap();
        assert_eq!(value, Value::U8(0));
        // Signed extrema.
        let s16 = super::Node {
            name: "mmio:266:2:y".into(),
            source: Source::Mmio { offset: 0x10a, size: 2 },
            width_bits: 16,
        };
        let min_pattern = 1u64 << 15;
        let value = generate_satisfying(
            &Predicate::Ge(min_pattern, Signedness::Signed), &s16, None, &mut make_rng(1),
        )
        .unwrap();
        assert_eq!(value, Value::U16(min_pattern as u16));
        let max_signed = max_signed_for_width(16) as u64;
        let value = generate_satisfying(
            &Predicate::Le(max_signed, Signedness::Signed), &s16, None, &mut make_rng(1),
        )
        .unwrap();
        assert_eq!(value, Value::U16(max_signed as u16));
        // Gt(MAX) and Lt(MIN) have no representable target.
        let mut rng = make_rng(1);
        assert!(generate_satisfying(&Predicate::Gt(255, Signedness::Unsigned), &node, None, &mut rng).is_err());
        assert!(generate_satisfying(&Predicate::Lt(min_pattern, Signedness::Signed), &s16, None, &mut rng).is_err());
    }

    #[test]
    fn value_width_rejects_out_of_domain() {
        assert!(Value::from_u64(0x1ff, 8).is_err());
        assert!(Value::from_u64(0x1_ffff, 16).is_err());
        assert!(Value::from_u64(0x1_ffff_ffff, 32).is_err());
        assert!(Value::from_u64(1, 0).is_err(), "zero width is rejected");
        assert!(Value::from_u64(1, 65).is_err(), "oversize width is rejected");
        assert_eq!(Value::from_u64(0xff, 8).unwrap(), Value::U8(0xff));
        assert_eq!(Value::from_u64(0xffff, 16).unwrap(), Value::U16(0xffff));
        assert_eq!(Value::from_u64(0xffffffff, 32).unwrap(), Value::U32(0xffffffff));
    }

    #[test]
    fn all_predicates_are_satisfiable() {
        assert!(Predicate::BitSet(3).satisfied_by(0b1000, 8));
        assert!(Predicate::BitClear(3).satisfied_by(0b0111, 8));
        assert!(Predicate::Eq(42).satisfied_by(42, 8));
        assert!(Predicate::Ne(42).satisfied_by(43, 8));
        assert!(Predicate::Gt(10, Signedness::Unsigned).satisfied_by(11, 8));
        assert!(Predicate::Lt(10, Signedness::Unsigned).satisfied_by(9, 8));
        assert!(Predicate::Ge(10, Signedness::Unsigned).satisfied_by(10, 8));
        assert!(Predicate::Le(10, Signedness::Unsigned).satisfied_by(10, 8));
        assert!(Predicate::InRange(5, 7, Signedness::Unsigned).satisfied_by(6, 8));
    }

    #[test]
    fn checked_boundary_rejects_unreachable_target() {
        let rule = parse_rule(
            "rule rule:max_u8|target:mmio:256:1:x|predicate:gt:unsigned:255\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound gt unsigned 255\n\
             mutation set_boundary above\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut rng = make_rng(1);
        // Gt(255) on an 8-bit unsigned value has no representable target.
        assert!(sdg.generate(&mut rng).is_err());
    }

    #[test]
    fn generator_satisfies_at_least_one_precondition() {
        let rule = parse_rule(
            "rule rule:two_features|target:mmio:256:1:x|predicate:gt:unsigned:40\n\
             node mmio:16:4:f mmio 0x10 4\n\
             node mmio:256:1:x mmio 0x100 1\n\
             precondition mmio:16:4:f mmio:256:1:x head_guard bit_set 5\n\
             precondition mmio:16:4:f mmio:256:1:x head_guard bit_set 7\n\
             trigger mmio:256:1:x head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut rng = make_rng(0);
        for _ in 0..32 {
            let scenario = sdg.generate(&mut rng).unwrap();
            let f = scenario.value("mmio:16:4:f").unwrap().as_u64().unwrap();
            assert!(f & (1 << 5) != 0 || f & (1 << 7) != 0,
                    "at least one precondition must hold: {f:x}");
            let x = scenario.value("mmio:256:1:x").unwrap().as_u64().unwrap();
            assert!(x > 40, "target state must hold: {x}");
        }
    }

    #[test]
    fn generator_rejects_value_outside_width() {
        let rule = parse_rule(
            "rule rule:narrow|target:mmio:256:1:x|predicate:eq:511\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound eq 511\n\
             mutation set_value 511\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut rng = make_rng(0);
        // Values outside the declared width are rejected rather than wrapped
        // or truncated.
        assert!(sdg.generate(&mut rng).is_err());
    }

    #[test]
    fn generator_rejects_zero_width_nodes() {
        let rule = parse_rule(
            "rule rule:zero|target:mmio:0:0:x|predicate:eq:0\n\
             node mmio:0:0:x mmio 0x0 0\n\
             trigger mmio:0:0:x head_bound eq 0\n\
             mutation keep\n",
        );
        assert!(rule.is_err(), "zero-width nodes are rejected");
    }

    #[test]
    fn lowering_is_deterministic_for_fixed_rng() {
        let rule = parse_rule(
            "rule rule:order|target:mmio:256:1:a|predicate:gt:unsigned:0\n\
             node mmio:260:1:b mmio 0x104 1\n\
             node mmio:256:1:a mmio 0x100 1\n\
             trigger mmio:256:1:a head_bound gt unsigned 0\n\
             mutation set_boundary above\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut rng = make_rng(7);
        let scenario = sdg.generate(&mut rng).unwrap();
        let mut rng2 = make_rng(7);
        let scenario2 = sdg.generate(&mut rng2).unwrap();
        assert_eq!(scenario.values, scenario2.values);
        assert_eq!(scenario.placements, scenario2.placements);
    }

    #[test]
    fn lowering_draws_independent_random_visits() {
        // Two same-word mmio fields: each field independently draws a random
        // target visit. Generation insertion order (precondition var first,
        // then target) and canonical node order must not encode consecutive
        // or recoverable visits.
        let rule = parse_rule(
            "rule rule:visits|target:mmio:256:1:a|predicate:gt:unsigned:40\n\
             node mmio:256:1:a mmio 0x100 1\n\
             node mmio:257:1:b mmio 0x101 1\n\
             precondition mmio:257:1:b mmio:256:1:a head_guard bit_set 1\n\
             trigger mmio:256:1:a head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut shared = false;
        let mut distinct = false;
        for seed in 0..64u64 {
            let mut rng = make_rng(seed);
            let mut scenario = sdg.generate(&mut rng).unwrap();
            let input = lower_scenario(&mut scenario, &sdg.rules[0], &mut make_rng(7)).unwrap();
            let model = &input.mmio.word_models[0];
            let visit_a = scenario.placements.get("mmio:256:1:a").unwrap().visit;
            let visit_b = scenario.placements.get("mmio:257:1:b").unwrap().visit;
            assert!(visit_a < model.values.len() && visit_b < model.values.len());
            // Every recorded visit reads back the stored value.
            let read_a = super::read_bytes_at(&input.mmio.word_models, 0x100, 1, visit_a).unwrap();
            let read_b = super::read_bytes_at(&input.mmio.word_models, 0x101, 1, visit_b).unwrap();
            assert_eq!(read_a, scenario.value("mmio:256:1:a").unwrap().as_u64().unwrap());
            assert_eq!(read_b, scenario.value("mmio:257:1:b").unwrap().as_u64().unwrap());
            if visit_a == visit_b {
                shared = true;
            } else {
                distinct = true;
            }
        }
        assert!(shared, "some generations mask-merge the shared word visit");
        assert!(distinct, "some generations place the fields on different visits");
    }

    #[test]
    fn same_word_same_visit_fields_are_mask_merged() {
        // Two same-word mmio fields assigned the same visit: lowering
        // mask-merges them into one visit word; they are never appended as
        // separate visits.
        let rule = parse_rule(
            "rule rule:merge|target:mmio:256:1:a|predicate:gt:unsigned:40\n\
             node mmio:256:1:a mmio 0x100 1\n\
             node mmio:257:1:b mmio 0x101 1\n\
             precondition mmio:257:1:b mmio:256:1:a head_guard bit_set 1\n\
             trigger mmio:256:1:a head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        ).unwrap();
        let mut scenario = SemanticScenario {
            target_rule: "rule:merge|target:mmio:256:1:a|predicate:gt:unsigned:40".into(),
            ..Default::default()
        };
        for node in &rule.nodes {
            scenario.insert_node(node.clone());
        }
        scenario.set("mmio:256:1:a".into(), Value::U8(41));
        scenario.set("mmio:257:1:b".into(), Value::U8(0xab));
        scenario.insert_placement("mmio:256:1:a", Placement { region: 0, visit: 1 });
        scenario.insert_placement("mmio:257:1:b", Placement { region: 0, visit: 1 });
        let input = lower_scenario(&mut scenario, &rule, &mut make_rng(9)).unwrap();
        let model = &input.mmio.word_models[0];
        assert_eq!(model.offset, 0x100);
        // Both fields share visit 1: the model carries exactly two visits
        // (the random padding and the shared visit), not one visit per field.
        assert_eq!(model.values.len(), 2, "same-word same-visit fields are mask-merged, not appended");
        // Both byte ranges live in the shared visit word.
        let word = model.values[1];
        assert_eq!(word & 0xff, 41);
        assert_eq!((word >> 8) & 0xff, 0xab);
        // Each field reads back through the shared visit.
        let lifted = super::lift_with(&input, &rule, &scenario.placements).unwrap();
        assert_eq!(lifted.values.get("mmio:256:1:a").unwrap().as_u64().unwrap(), 41);
        assert_eq!(lifted.values.get("mmio:257:1:b").unwrap().as_u64().unwrap(), 0xab);
        assert!(input.is_valid());
    }

    #[test]
    fn mutator_preserves_precondition() {
        let rule = parse_rule(
            "rule rule:preserve|target:mmio:256:1:x|predicate:gt:unsigned:40\n\
             node mmio:16:4:f mmio 0x10 4\n\
             node mmio:256:1:x mmio 0x100 1\n\
             precondition mmio:16:4:f mmio:256:1:x head_guard bit_set 5\n\
             trigger mmio:256:1:x head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut rng = make_rng(0);
        let mut scenario = sdg.generate(&mut rng).unwrap();
        let input = lower_scenario(&mut scenario, &sdg.rules[0], &mut make_rng(99)).unwrap();
        let mut mutated = input.clone();
        // Seed RNG so that the rule-aware path mutates x.
        let mut rng = make_rng(3);
        assert!(sdg.mutate_scenario(&mut rng, &mut mutated, &scenario).is_some());
        assert_ne!(mutated, input);
    }

    #[test]
    fn mutation_preserves_placement_and_skeleton() {
        let rule = parse_rule(
            "rule rule:preserve|target:mmio:256:1:x|predicate:gt:unsigned:40\n\
             node mmio:16:4:f mmio 0x10 4\n\
             node mmio:256:1:x mmio 0x100 1\n\
             precondition mmio:16:4:f mmio:256:1:x head_guard bit_set 5\n\
             trigger mmio:256:1:x head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut rng = make_rng(0);
        let mut scenario = sdg.generate(&mut rng).unwrap();
        let mut input = lower_scenario(&mut scenario, &sdg.rules[0], &mut make_rng(99)).unwrap();
        let skeleton = input.mmio.word_models.clone();
        let mut mutated_any = false;
        for seed in 0..32u64 {
            let mut rng = make_rng(seed);
            if let Some(child) = sdg.mutate_scenario(&mut rng, &mut input, &scenario) {
                mutated_any = true;
                // The modelled slot set and visit counts never change.
                let offsets: Vec<u32> = input.mmio.word_models.iter().map(|m| m.offset).collect();
                let expected: Vec<u32> = skeleton.iter().map(|m| m.offset).collect();
                assert_eq!(offsets, expected, "skeleton must be preserved");
                for (model, original) in input.mmio.word_models.iter().zip(skeleton.iter()) {
                    assert_eq!(model.values.len(), original.values.len(), "visit counts must be preserved");
                }
                // The exact placements are preserved in the child scenario.
                assert_eq!(child.placements, scenario.placements, "placements must be preserved");
                // The target value must satisfy the trigger after mutation.
                let x = child.values.get("mmio:256:1:x").unwrap().as_u64().unwrap();
                assert!(x > 40, "target state must hold after mutation: {x}");
                let f = child.values.get("mmio:16:4:f").unwrap().as_u64().unwrap();
                assert!(f & (1 << 5) != 0, "precondition must be preserved: {f:x}");
                // The child scenario reads back from the mutated wire.
                let lifted = super::lift_with(&input, &sdg.rules[0], &child.placements).unwrap();
                assert_eq!(lifted.values, child.values, "the child scenario must lift back from the wire");
            }
        }
        assert!(mutated_any, "mutation should eventually apply");
    }

    #[test]
    fn cross_rule_merge_validates_complete_states() {
        let primary = parse_rule(
            "rule rule:primary|target:mmio:256:1:x|predicate:gt:unsigned:40\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        ).unwrap();
        let secondary = parse_rule(
            "rule rule:secondary|target:mmio:260:1:y|predicate:lt:unsigned:10\n\
             node mmio:260:1:y mmio 0x104 1\n\
             precondition mmio:260:1:y mmio:260:1:y head_guard bit_set 3\n\
             trigger mmio:260:1:y head_bound lt unsigned 10\n\
             mutation set_value 9\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![primary, secondary] };
        // A scenario that targets the primary rule explicitly.
        let mut scenario = SemanticScenario {
            target_rule: sdg.rules[0].name.clone(),
            ..Default::default()
        };
        for node in &sdg.rules[0].nodes {
            scenario.insert_node(node.clone());
        }
        scenario.set("mmio:256:1:x".into(), Value::U8(41));
        let mut merged = false;
        for seed in 0..128u64 {
            let mut trial_scenario = scenario.clone();
            let mut input = lower_scenario(&mut trial_scenario, &sdg.rules[0], &mut make_rng(99)).unwrap();
            let mut rng = make_rng(seed);
            if let Some(child) = sdg.mutate_scenario(&mut rng, &mut input, &trial_scenario) {
                // The complete primary rule state must hold.
                let x = child.values.get("mmio:256:1:x").unwrap().as_u64().unwrap();
                assert!(x > 40, "primary target must still hold");
                // When the secondary rule's nodes were merged in, its
                // complete state must hold: target state and at least one
                // precondition.
                if let Some(y) = child.values.get("mmio:260:1:y") {
                    let y = y.as_u64().unwrap();
                    assert!(y < 10, "secondary target must hold: {y}");
                    assert!(y & (1 << 3) != 0, "secondary precondition must hold: {y}");
                    merged = true;
                    break;
                }
            }
        }
        assert!(merged, "cross-rule merge should satisfy both complete rule states");
    }

    #[test]
    fn cross_rule_merge_skips_conflicting_secondary_atomically() {
        // The secondary target contradicts the primary: eq 40 vs gt 40 on the
        // same variable. The merge must be skipped atomically.
        let primary = parse_rule(
            "rule rule:primary|target:mmio:256:1:x|predicate:gt:unsigned:40\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        ).unwrap();
        let conflicting = parse_rule(
            "rule rule:conflicting|target:mmio:256:1:x|predicate:eq:40\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound eq 40\n\
             mutation set_value 40\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![primary, conflicting] };
        let mut scenario = SemanticScenario {
            target_rule: sdg.rules[0].name.clone(),
            ..Default::default()
        };
        for node in &sdg.rules[0].nodes {
            scenario.insert_node(node.clone());
        }
        scenario.set("mmio:256:1:x".into(), Value::U8(41));
        for seed in 0..128u64 {
            let mut trial_scenario = scenario.clone();
            let mut input = lower_scenario(&mut trial_scenario, &sdg.rules[0], &mut make_rng(99)).unwrap();
            let mut rng = make_rng(seed);
            let _ = sdg.mutate_scenario(&mut rng, &mut input, &trial_scenario);
            // A committed mutation always holds the complete state of the
            // rule it targeted; a conflicting merge never corrupts it.
            let primary_ok = super::rule_state_satisfied(&input, &sdg.rules[0], &trial_scenario);
            let conflicting_ok = super::rule_state_satisfied(&input, &sdg.rules[1], &trial_scenario);
            assert!(
                primary_ok || conflicting_ok,
                "the targeted rule's complete state must hold after mutation"
            );
            if primary_ok {
                let lifted = super::lift_with(&input, &sdg.rules[0], &trial_scenario.placements).unwrap();
                let x = lifted.values.get("mmio:256:1:x").unwrap().as_u64().unwrap();
                assert!(x > 40, "conflicting cross-rule merge must never contradict the primary target: {x}");
            }
        }
    }

    #[test]
    fn bytes_payload_enforces_node_width() {
        // A size_bytes=2 node accepts at most a 2-byte payload.
        let node = super::Node {
            name: "streaming:0:4:2:virtio_net_hdr.gso_size".into(),
            source: Source::Streaming { slot: 0, offset: 0x4, size: 2 },
            width_bits: 16,
        };
        let mut scenario = SemanticScenario {
            target_rule: "rule:p|target:streaming:0:4:2:virtio_net_hdr.gso_size|predicate:eq:0".into(),
            ..Default::default()
        };
        scenario.insert_node(node.clone());
        scenario.set(node.name.clone(), Value::Bytes(vec![0x11, 0x22]));
        let rule = payload_rule();
        let input = lower_scenario(&mut scenario, &rule, &mut make_rng(5)).unwrap();
        let unit = &input.dma.streaming[0];
        // The streaming visit is 0: mapped buffers fill once.
        let read = super::read_bytes_at(&unit.word_models, 0x4, 2, 0).unwrap();
        assert_eq!(read, 0x2211);
        assert!(input.is_valid());
        // A 3-byte payload is rejected rather than truncated.
        scenario.set(node.name.clone(), Value::Bytes(vec![0x11, 0x22, 0x33]));
        assert!(lower_scenario(&mut scenario, &rule, &mut make_rng(5)).is_err(),
                "payloads outside the node width must be rejected");
    }

    fn payload_rule() -> super::Rule {
        parse_rule(
            "rule rule:payload|target:streaming:0:4:2:virtio_net_hdr.gso_size|predicate:eq:0\n\
             node streaming:0:4:2:virtio_net_hdr.gso_size streaming 0 0x4 2\n\
             trigger streaming:0:4:2:virtio_net_hdr.gso_size head_bound eq 0\n\
             mutation set_value 0\n",
        ).unwrap()
    }

    #[test]
    fn u64_lowering_splits_cross_word_fields() {
        let rule = parse_rule(
            "rule rule:wide|target:mmio:262:8:w|predicate:eq:0\n\
             node mmio:262:8:w mmio 0x106 8\n\
             trigger mmio:262:8:w head_bound eq 0\n\
             mutation set_value 0\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut scenario = SemanticScenario {
            target_rule: sdg.rules[0].name.clone(),
            ..Default::default()
        };
        scenario.insert_node(sdg.rules[0].nodes[0].clone());
        scenario.set("mmio:262:8:w".into(), Value::U64(0x0000_0004_0002_0001));
        let input = lower_scenario(&mut scenario, &sdg.rules[0], &mut make_rng(5)).unwrap();
        // The 8-byte field at offset 0x106 spans the 0x104, 0x108 and 0x10c
        // words.
        let offsets: Vec<u32> = input.mmio.word_models.iter().map(|m| m.offset).collect();
        assert_eq!(offsets, vec![0x104, 0x108, 0x10c], "cross-word fields split per word");
        // The lowered field occupies one recorded visit per word; read it
        // back through the exact placement.
        let visit = scenario.placements.get("mmio:262:8:w").unwrap().visit;
        let read = super::read_bytes_at(&input.mmio.word_models, 0x106, 8, visit).unwrap();
        assert_eq!(read, 0x0000_0004_0002_0001);
        assert!(input.is_valid());
    }

    #[test]
    fn every_mutation_hint_is_honored_end_to_end() {
        let mmio_node = |name: &str, offset: u32, size: u8| super::Node {
            name: name.into(),
            source: Source::Mmio { offset, size },
            width_bits: size * 8,
        };
        // (predicate, hint) pairs mapped by the SDG hint table.
        let cases: Vec<(Predicate, Mutation)> = vec![
            (Predicate::Gt(40, Signedness::Unsigned), Mutation::SetBoundary(BoundarySide::Above)),
            (Predicate::Lt(40, Signedness::Unsigned), Mutation::SetBoundary(BoundarySide::Below)),
            (Predicate::Ge(40, Signedness::Unsigned), Mutation::SetBoundary(BoundarySide::Above)),
            (Predicate::Le(40, Signedness::Unsigned), Mutation::SetBoundary(BoundarySide::Below)),
            (Predicate::Eq(42, ), Mutation::SetValue(42)),
            (Predicate::BitSet(5), Mutation::SetBits(1u64 << 5)),
            (Predicate::BitClear(5), Mutation::ClearBits(1u64 << 5)),
            (Predicate::InRange(5, 9, Signedness::Unsigned), Mutation::SampleRange(5, 9)),
            // Operators outside the hint table must still execute.
            (Predicate::Gt(40, Signedness::Unsigned), Mutation::Inc(3)),
            (Predicate::Lt(40, Signedness::Unsigned), Mutation::Dec(3)),
            (Predicate::Le(255, Signedness::Unsigned), Mutation::SetBoundary(BoundarySide::Max)),
            (Predicate::Ge(0, Signedness::Unsigned), Mutation::SetBoundary(BoundarySide::Min)),
        ];
        for (index, (predicate, hint)) in cases.iter().enumerate() {
            let offset = 0x100u32 + (index as u32) * 4;
            let name = format!("mmio:{}:1:x{index}", offset);
            let node = mmio_node(&name, offset, 1);
            let mut scenario = SemanticScenario {
                target_rule: format!("rule:p|target:{name}|predicate:x"),
                ..Default::default()
            };
            scenario.insert_node(node.clone());
            // Seed the base value: set 41 so boundary/arith operators move
            // across the threshold.
            scenario.set(name.clone(), Value::U8(41));
            let value = super::apply_mutation_hint(predicate, &node, hint, Some(41), &mut make_rng(index as u64))
                .unwrap_or_else(|e| panic!("hint {hint:?} must execute: {e}"));
            let v = value.as_u64().unwrap();
            assert!(
                predicate.satisfied_by(v, 8),
                "hint {hint:?} must reach predicate {predicate:?}: got {v}"
            );
        }
    }

    #[test]
    fn incompatible_hint_is_rejected_not_substituted() {
        let node = super::Node {
            name: "mmio:256:1:x".into(),
            source: Source::Mmio { offset: 0x100, size: 1 },
            width_bits: 8,
        };
        // Dec cannot reach Gt(40) from 41: rejection, never a substituted
        // value.
        let result = super::apply_mutation_hint(
            &Predicate::Gt(40, Signedness::Unsigned), &node, &Mutation::Dec(3), Some(41), &mut make_rng(1),
        );
        assert!(result.is_err(), "Dec cannot reach Gt(40) from 41 and must be rejected");
        // FlipBit from a bit-set base cannot reach BitSet: rejection.
        let result = super::apply_mutation_hint(
            &Predicate::BitSet(5), &node, &Mutation::FlipBit(5), Some(0xff), &mut make_rng(1),
        );
        assert!(result.is_err(), "FlipBit from a bit-set base cannot reach BitSet and must be rejected");
        // The same rejections apply to the rule-aware mutator operator.
        let result = super::apply_mutation(
            41, &node, &Predicate::Gt(40, Signedness::Unsigned), &Mutation::Dec(3), &mut make_rng(1),
        );
        assert!(result.is_err(), "the mutator must reject Dec against Gt(40)");
        let result = super::apply_mutation(
            0xff, &node, &Predicate::BitSet(5), &Mutation::FlipBit(5), &mut make_rng(1),
        );
        assert!(result.is_err(), "the mutator must reject FlipBit that clears the target bit");
    }

    #[test]
    fn generation_rejects_incompatible_hint_rules() {
        // A rule whose hint cannot reach the target state must fail
        // generation explicitly.
        let rule = parse_rule(
            "rule rule:bad_hint|target:mmio:256:1:x|predicate:gt:unsigned:40\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound gt unsigned 40\n\
             mutation dec 3\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut rng = make_rng(0);
        assert!(sdg.generate(&mut rng).is_err(),
                "a Dec hint against a Gt target must be rejected");
    }

    #[test]
    fn flipbit_generation_reaches_state_from_bit_clear_base() {
        let node = super::Node {
            name: "mmio:256:1:x".into(),
            source: Source::Mmio { offset: 0x100, size: 1 },
            width_bits: 8,
        };
        // FlipBit(5) from a base with bit 5 clear reaches BitSet(5).
        let value = super::apply_mutation_hint(
            &Predicate::BitSet(5), &node, &Mutation::FlipBit(5), Some(0x00), &mut make_rng(1),
        )
        .unwrap();
        assert!(Predicate::BitSet(5).satisfied_by(value.as_u64().unwrap(), 8));
        // ... and reaches BitClear(5) from a base with bit 5 set.
        let value = super::apply_mutation_hint(
            &Predicate::BitClear(5), &node, &Mutation::FlipBit(5), Some(0xff), &mut make_rng(1),
        )
        .unwrap();
        assert!(Predicate::BitClear(5).satisfied_by(value.as_u64().unwrap(), 8));
    }

    #[test]
    fn signed_samplerange_in_rule_aware_mutation() {
        // Encoded signed [-10, 10] is [65526, 10]: the mutator must sample
        // under signed ordering instead of skipping.
        let rule = parse_rule(
            "rule rule:signed_range|target:mmio:266:2:y|predicate:in_range:signed:65526:10\n\
             node mmio:266:2:y mmio 0x10a 2\n\
             trigger mmio:266:2:y head_bound in_range signed 65526 10\n\
             mutation sample_range 65526 10\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut rng = make_rng(0);
        let mut scenario = sdg.generate(&mut rng).unwrap();
        assert!(scenario.value("mmio:266:2:y").is_some(), "generation must satisfy the signed range");
        let mut mutated_any = false;
        for seed in 0..64u64 {
            let mut input = lower_scenario(&mut scenario, &sdg.rules[0], &mut make_rng(99)).unwrap();
            let mut rng = make_rng(seed);
            if let Some(child) = sdg.mutate_scenario(&mut rng, &mut input, &scenario) {
                mutated_any = true;
                let y = child.values.get("mmio:266:2:y").unwrap().as_u64().unwrap();
                let signed = signed_value(y, 16, Signedness::Signed);
                assert!((-10..=10).contains(&signed),
                        "rule-aware mutation must stay inside the signed range: {signed}");
            }
        }
        assert!(mutated_any, "signed rule-aware mutation must apply");
    }

    #[test]
    fn generated_inrange_sampling_is_inclusive() {
        let node = super::Node {
            name: "mmio:256:1:x".into(),
            source: Source::Mmio { offset: 0x100, size: 1 },
            width_bits: 8,
        };
        for seed in 0..64u64 {
            let mut rng = make_rng(seed);
            let value = generate_satisfying(
                &Predicate::InRange(5, 7, Signedness::Unsigned), &node, None, &mut rng,
            )
            .unwrap();
            assert!((5..=7).contains(&value.as_u64().unwrap()), "sampling must be inclusive: {value:?}");
        }
    }

    #[test]
    fn generated_inrange_sampling_is_signed_ordered() {
        let node = super::Node {
            name: "mmio:266:2:y".into(),
            source: Source::Mmio { offset: 0x10a, size: 2 },
            width_bits: 16,
        };
        for seed in 0..64u64 {
            let mut rng = make_rng(seed);
            let value = generate_satisfying(
                &Predicate::InRange(0xfff6, 0x000a, Signedness::Signed), &node, None, &mut rng,
            )
            .unwrap();
            let v = value.as_u64().unwrap();
            let signed = signed_value(v, 16, Signedness::Signed);
            assert!((-10..=10).contains(&signed), "signed sampling must stay inside the range: {signed}");
        }
    }

    #[test]
    fn streaming_slot_groups_one_buffer_and_region_varies() {
        let rule = parse_rule(
            "rule rule:hdr|target:streaming:0:4:2:virtio_net_hdr.gso_size|predicate:eq:0\n\
             node streaming:0:4:2:virtio_net_hdr.gso_size streaming 0 0x4 2\n\
             node streaming:0:6:2:virtio_net_hdr.csum_start streaming 0 0x6 2\n\
             node streaming:1:0:1:virtio_net_ctrl_hdr.class streaming 1 0x0 1\n\
             trigger streaming:0:4:2:virtio_net_hdr.gso_size head_bound eq 0\n\
             mutation set_value 0\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut rng = make_rng(3);
        let mut scenario = sdg.generate(&mut rng).unwrap();
        let input = lower_scenario(&mut scenario, &sdg.rules[0], &mut make_rng(7)).unwrap();
        // Fields sharing one protocol slot model one buffer.
        assert_eq!(input.dma.streaming.len(), 2, "one unit per protocol slot");
        // The runtime mapping ordinals are distinct and never equal a slot
        // number chosen by the protocol.
        let ordinals: Vec<u64> = input.dma.streaming.iter().map(|u| u.addr).collect();
        assert_ne!(ordinals[0], ordinals[1], "mapping ordinals vary per slot group");
        // Deterministic for a fixed RNG.
        let input2 = lower_scenario(&mut scenario, &sdg.rules[0], &mut make_rng(7)).unwrap();
        let ordinals2: Vec<u64> = input2.dma.streaming.iter().map(|u| u.addr).collect();
        assert_eq!(ordinals, ordinals2, "mapping ordinals are reproducible for a fixed RNG");
        // A different generation RNG can select different ordinals: the
        // slot regions are chosen once at generation and then honored.
        let mut any_different = false;
        for seed in 0..32u64 {
            let mut other_scenario = sdg.generate(&mut make_rng(100 + seed)).unwrap();
            let other = lower_scenario(&mut other_scenario, &sdg.rules[0], &mut make_rng(7)).unwrap();
            let other_ordinals: Vec<u64> = other.dma.streaming.iter().map(|u| u.addr).collect();
            if other_ordinals != ordinals {
                any_different = true;
                break;
            }
        }
        assert!(any_different, "mapping ordinals vary with the generation RNG");
        assert!(input.is_valid());
    }

    #[test]
    fn streaming_buffers_fill_once_without_visit_sequences() {
        let rule = parse_rule(
            "rule rule:hdr|target:streaming:0:4:2:virtio_net_hdr.gso_size|predicate:eq:0\n\
             node streaming:0:4:2:virtio_net_hdr.gso_size streaming 0 0x4 2\n\
             node streaming:0:6:2:virtio_net_hdr.csum_start streaming 0 0x6 2\n\
             trigger streaming:0:4:2:virtio_net_hdr.gso_size head_bound eq 0\n\
             mutation set_value 0\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut rng = make_rng(3);
        let mut scenario = sdg.generate(&mut rng).unwrap();
        let input = lower_scenario(&mut scenario, &sdg.rules[0], &mut make_rng(7)).unwrap();
        // A mapped streaming buffer fills once: every modelled word carries
        // exactly one value.
        for unit in &input.dma.streaming {
            for model in &unit.word_models {
                assert_eq!(model.values.len(), 1, "streaming words fill once");
            }
        }
        assert!(input.is_valid());
    }

    #[test]
    fn mutation_updates_original_target_visit_only() {
        // Two same-word fields assigned different visits: the target is not
        // on the final visit. Mutation must update the original target visit
        // only and preserve every other visit byte.
        let target = super::Node {
            name: "mmio:257:1:low".into(),
            source: Source::Mmio { offset: 0x101, size: 1 },
            width_bits: 8,
        };
        let other = super::Node {
            name: "mmio:258:1:high".into(),
            source: Source::Mmio { offset: 0x102, size: 1 },
            width_bits: 8,
        };
        let mut scenario = SemanticScenario {
            target_rule: "rule:preserve|target:mmio:257:1:low|predicate:gt:unsigned:40".into(),
            ..Default::default()
        };
        scenario.insert_node(target.clone());
        scenario.insert_node(other.clone());
        // The target occupies visit 0; the other field visit 2.
        scenario.insert_placement(&target.name, Placement { region: 0, visit: 0 });
        scenario.insert_placement(&other.name, Placement { region: 0, visit: 2 });
        scenario.set(target.name.clone(), Value::U8(41));
        scenario.set(other.name.clone(), Value::U8(3));
        let rule = parse_preservation_rule();
        let input = lower_scenario(&mut scenario, &rule, &mut make_rng(9)).unwrap();
        let model = &input.mmio.word_models[0];
        assert_eq!(model.offset, 0x100);
        assert!(model.values.len() >= 3, "both visits must be present");
        let before: Vec<u32> = model.values.clone();
        // Lift honors the recorded placements.
        let lifted = super::lift_with(&input, &rule, &scenario.placements).unwrap();
        let low = lifted.values.get("mmio:257:1:low").unwrap().as_u64().unwrap();
        assert_eq!(low, u64::from((before[0] >> 8) & 0xff), "the target is read from visit 0, not the final visit");
        let _ = other;
        // Rule-aware mutation updates visit 0 only and preserves every
        // other visit byte.
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut mutated = input.clone();
        let mut mutated_any = false;
        for seed in 0..64u64 {
            let mut rng = make_rng(seed);
            let mut trial = input.clone();
            if sdg.mutate_scenario(&mut rng, &mut trial, &scenario).is_some() {
                mutated = trial;
                mutated_any = true;
                break;
            }
        }
        assert!(mutated_any, "mutation should eventually apply");
        let model = &mutated.mmio.word_models[0];
        let new_low = (model.values[0] >> 8) & 0xff;
        let old_low = (before[0] >> 8) & 0xff;
        assert_ne!(new_low, old_low, "the original target visit changed");
        assert!(new_low > 40, "the mutated target satisfies the trigger: {new_low}");
        for (index, (word, original)) in model.values.iter().zip(before.iter()).enumerate() {
            if index == 0 {
                let mask = !(0xffu32 << 8);
                assert_eq!(word & mask, original & mask, "other bytes in the target visit are preserved");
            } else {
                assert_eq!(word, original, "every other visit byte is preserved");
            }
        }

    }

    fn parse_preservation_rule() -> super::Rule {
        parse_rule(
            "rule rule:preserve|target:mmio:257:1:low|predicate:gt:unsigned:40\n\
             node mmio:257:1:low mmio 0x101 1\n\
             node mmio:258:1:high mmio 0x102 1\n\
             precondition mmio:258:1:high mmio:257:1:low head_guard bit_set 1\n\
             trigger mmio:257:1:low head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        ).unwrap()
    }

    #[test]
    fn slot_region_mapping_keeps_slots_separate() {
        // Protocol slots map to runtime regions explicitly: a region ordinal
        // that numerically equals another slot's number never conflates the
        // two buffers.
        let rule = parse_rule(
            "rule rule:slots|target:streaming:0:4:2:virtio_net_hdr.gso_size|predicate:eq:0\n\
             node streaming:0:4:2:virtio_net_hdr.gso_size streaming 0 0x4 2\n\
             node streaming:3:0:1:virtio_net_ctrl_ack.ack streaming 3 0x0 1\n\
             trigger streaming:0:4:2:virtio_net_hdr.gso_size head_bound eq 0\n\
             mutation set_value 0\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![rule] };
        let mut rng = make_rng(21);
        let scenario = sdg.generate(&mut rng).unwrap();
        // Force a crossing: slot 0 maps to region 3 and slot 3 to region 0.
        let mut scenario = scenario;
        scenario.slot_regions.insert(0, 3);
        scenario.slot_regions.insert(3, 0);
        let input = lower_scenario(&mut scenario, &sdg.rules[0], &mut make_rng(7)).unwrap();
        // One unit per slot group, at the mapped regions.
        assert_eq!(input.dma.streaming.len(), 2);
        let addrs: Vec<u64> = input.dma.streaming.iter().map(|u| u.addr).collect();
        assert!(addrs.contains(&3) && addrs.contains(&0), "the mapped regions are honored: {addrs:?}");
        // Each slot's field lives in its own buffer.
        let gso_unit = input.dma.streaming.iter().find(|u| u.addr == 3).unwrap();
        let ack_unit = input.dma.streaming.iter().find(|u| u.addr == 0).unwrap();
        assert!(gso_unit.word_models.iter().any(|m| m.offset == 0x4),
                "the slot-0 field is in the slot-0 group's buffer");
        assert!(ack_unit.word_models.iter().any(|m| m.offset == 0x0),
                "the slot-3 field is in the slot-3 group's buffer");
        assert!(input.is_valid());
    }

    #[test]
    fn cross_rule_insertion_reuses_existing_slot_group() {
        // The primary rule places slot 0 in a region; the secondary rule's
        // slot-0 field must join the same buffer.
        let primary = parse_rule(
            "rule rule:primary|target:streaming:0:4:2:virtio_net_hdr.gso_size|predicate:eq:0\n\
             node streaming:0:4:2:virtio_net_hdr.gso_size streaming 0 0x4 2\n\
             trigger streaming:0:4:2:virtio_net_hdr.gso_size head_bound eq 0\n\
             mutation set_value 0\n",
        ).unwrap();
        let secondary = parse_rule(
            "rule rule:secondary|target:streaming:0:6:2:virtio_net_hdr.csum_start|predicate:eq:1\n\
             node streaming:0:6:2:virtio_net_hdr.csum_start streaming 0 0x6 2\n\
             precondition streaming:0:6:2:virtio_net_hdr.csum_start streaming:0:6:2:virtio_net_hdr.csum_start head_guard bit_set 0\n\
             trigger streaming:0:6:2:virtio_net_hdr.csum_start head_bound eq 1\n\
             mutation set_value 1\n",
        ).unwrap();
        let sdg = SemanticDependencyGraph { rules: vec![primary, secondary] };
        let mut rng = make_rng(5);
        let scenario = sdg.generate(&mut rng).unwrap();
        let mut merged = false;
        for seed in 0..128u64 {
            let mut trial_scenario = scenario.clone();
            let mut input = lower_scenario(&mut trial_scenario, &sdg.rules[0], &mut make_rng(99)).unwrap();
            let mut rng = make_rng(seed);
            if let Some(child) = sdg.mutate_scenario(&mut rng, &mut input, &trial_scenario) {
                // When the secondary's nodes were merged in, its slot-0
                // field joined the primary's slot-0 buffer.
                if child.value("streaming:0:6:2:virtio_net_hdr.csum_start").is_some() {
                    // One unit per slot: the merged field is in the same
                    // unit as the primary's slot-0 field. Both fields share
                    // the aligned word at 0x4 (offset 0x6 + 2 bytes spans
                    // its upper half).
                    assert_eq!(input.dma.streaming.len(), 1,
                               "the secondary's slot-0 field joins the existing slot-0 buffer");
                    let unit = &input.dma.streaming[0];
                    let model = unit.word_models.iter().find(|m| m.offset == 0x4)
                        .expect("the shared word model");
                    let gso = child
                        .value("streaming:0:4:2:virtio_net_hdr.gso_size")
                        .unwrap().as_u64().unwrap() as u32;
                    let csum = child
                        .value("streaming:0:6:2:virtio_net_hdr.csum_start")
                        .unwrap().as_u64().unwrap() as u32;
                    assert_eq!(model.values[0] & 0xffff, gso, "the primary field keeps its bytes");
                    assert_eq!(model.values[0] >> 16, csum, "the merged field is mask-merged in");
                    merged = true;
                    break;
                }
            }
        }
        assert!(merged, "cross-rule insertion into an existing slot group should work");
    }

    #[test]
    fn empty_rule_directory_selects_fallback() {
        let dir = std::env::temp_dir().join(format!(
            "sdg-empty-rules-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sdg = SemanticDependencyGraph::from_dir(&dir)
            .expect("an empty but valid rule directory is not an error");
        assert!(sdg.rules.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_rule_directory_is_an_error() {
        let dir = std::env::temp_dir().join(format!(
            "sdg-missing-rules-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(SemanticDependencyGraph::from_dir(&dir).is_err(),
                "a missing rule directory is a configuration error");
    }

    #[test]
    fn corrupted_seed_record_bytes_are_rejected() {
        let input = ScenarioInput::new(
            MmioSection { word_models: vec![word(0x110, &[0x7472_6976])] },
            crate::input::DmaSection::default(),
        );
        let encoded = crate::encoding::encode_scenario(&input);
        let record = crate::input::SeedRecord::new("rule:test".into(), 7, &encoded);
        let mut corrupted = encoded.clone();
        corrupted[0] ^= 0xff;
        // Exact replay rejects corrupted bytes before execution.
        assert!(record.verify(&encoded));
        assert!(!record.verify(&corrupted));
        let dir = std::env::temp_dir().join(format!(
            "sdg-seed-record-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seed.bin");
        std::fs::write(&path, &corrupted).unwrap();
        assert!(record.decode_file_verified(&path).is_err(), "corrupted seed bytes must not decode");
        std::fs::write(&path, &encoded).unwrap();
        assert!(record.decode_file_verified(&path).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn set_boundary_min_max_and_keep_hints_are_supported() {
        let node = super::Node {
            name: "mmio:256:1:x".into(),
            source: Source::Mmio { offset: 0x100, size: 1 },
            width_bits: 8,
        };
        // Min/Max set the domain extremes; the target predicates are the
        // ones the operators satisfy.
        let value = super::apply_mutation(41, &node, &Predicate::Ge(0, Signedness::Unsigned), &Mutation::SetBoundary(BoundarySide::Min), &mut make_rng(1)).unwrap();
        assert_eq!(value, Value::U8(0));
        let value = super::apply_mutation(41, &node, &Predicate::Le(255, Signedness::Unsigned), &Mutation::SetBoundary(BoundarySide::Max), &mut make_rng(1)).unwrap();
        assert_eq!(value, Value::U8(255));
        // Keep does not change the value.
        let value = super::apply_mutation(41, &node, &Predicate::Eq(41), &Mutation::Keep, &mut make_rng(1)).unwrap();
        assert_eq!(value, Value::U8(41));
        // Keep round-trips through the parser.
        let rule = parse_rule(
            "rule rule:keep|target:mmio:256:1:x|predicate:gt:unsigned:0\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound gt unsigned 0\n\
             mutation keep\n",
        ).unwrap();
        assert!(matches!(rule.mutation, Mutation::Keep));
        // set_boundary min/max round-trip through the parser.
        let rule = parse_rule(
            "rule rule:extremes|target:mmio:256:1:x|predicate:gt:unsigned:0\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound gt unsigned 0\n\
             mutation set_boundary min\n",
        ).unwrap();
        assert!(matches!(rule.mutation, Mutation::SetBoundary(BoundarySide::Min)));
        let rule = parse_rule(
            "rule rule:extremes2|target:mmio:256:1:x|predicate:gt:unsigned:0\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound gt unsigned 0\n\
             mutation set_boundary max\n",
        ).unwrap();
        assert!(matches!(rule.mutation, Mutation::SetBoundary(BoundarySide::Max)));
    }

    #[test]
    fn parse_predicate_tokens_rejects_unresolved() {
        assert!(parse_predicate_tokens(&["gt", "16"]).is_err());
        assert!(parse_predicate_tokens(&["in_range", "0", "10"]).is_err());
        assert!(parse_predicate_tokens(&["gt", "signed", "16"]).is_ok());
        assert!(parse_predicate_tokens(&["in_range", "unsigned", "0", "10"]).is_ok());
    }
}
