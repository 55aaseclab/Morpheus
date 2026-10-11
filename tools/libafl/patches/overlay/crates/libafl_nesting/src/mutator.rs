use alloc::borrow::Cow;
use core::num::NonZeroUsize;

use libafl::{
    Error,
    mutators::{MutationResult, Mutator},
};
use libafl_bolts::{Named, nonzero, rands::Rand};

use crate::{
    MAX_ENCODED_SCENARIO_BYTES,
    encoding::encode_scenario,
    generator::ScenarioGenerator,
    input::ScenarioInput,
};

const U32_BYTES: usize = core::mem::size_of::<u32>();

/// Docs §5.4: a small deterministic probability of random wire-format
/// mutation is kept even when the SDG is non-empty, to explore outside the
/// rule set. The decision draws from the fuzzer RNG, never from wall time.
const RANDOM_MUTATION_PROBABILITY: NonZeroUsize = nonzero!(16);

/// The L1 stub caps each raw testcase at `MAX_ENCODED_SCENARIO_BYTES` and
/// truncates anything longer, so a mutated scenario must stay within the
/// encoded budget. `extra_bytes` is the exact wire growth of the mutation.
fn fits_budget(input: &ScenarioInput, extra_bytes: usize) -> bool {
    encode_scenario(input).len() + extra_bytes <= MAX_ENCODED_SCENARIO_BYTES
}

/// Rule-aware mutator: mutation operates on the exact `SemanticScenario`
/// recorded for the parent's encoded bytes in the shared corpus metadata
/// store, re-lowers the target field to its stored placement, and registers
/// the child scenario for the child bytes. Wire-format seeds without
/// metadata never have a region or visit guessed from their layout; they
/// take the documented random fallback instead.
#[derive(Debug, Clone)]
pub struct ScenarioMutator {
    generator: ScenarioGenerator,
}

impl Default for ScenarioMutator {
    fn default() -> Self {
        Self::new(ScenarioGenerator::default())
    }
}

impl ScenarioMutator {
    #[must_use]
    pub fn new(generator: ScenarioGenerator) -> Self {
        Self { generator }
    }

    fn random_index<R: Rand>(rand: &mut R, len: usize) -> Option<usize> {
        if len == 0 {
            None
        } else {
            Some(rand.below(unsafe { NonZeroUsize::new_unchecked(len) }))
        }
    }

    fn mutate_u32<R: Rand>(rand: &mut R, value: &mut u32) {
        match rand.below(nonzero!(3)) {
            0 => *value ^= random_mask_u32(rand),
            1 => *value = value.rotate_left(1 + rand.below(nonzero!(31)) as u32),
            _ => *value = value.wrapping_add(1 + rand.below(nonzero!(65536)) as u32),
        }
        // Keep zero values available; do not force zero to become non-zero.
    }

    /// Whether the documented §5.4 probability selects random wire mutation.
    fn selects_random_wire_mutation<R: Rand>(rand: &mut R) -> bool {
        rand.below(RANDOM_MUTATION_PROBABILITY) == 0
    }

    /// The documented random wire-format mutation: skeleton metadata (the
    /// modelled slot set) stays fixed only within each op; the ops edit
    /// visit values, visit sequence lengths, coherent values and indexes,
    /// and whole streaming units. No op infers semantic placement.
    ///
    /// The mutation runs on a clone and commits only when the result is
    /// valid, in budget, and byte-different, so a skipped mutation leaves
    /// the input byte-for-byte unchanged.
    fn random_wire_mutate<R: Rand>(rand: &mut R, input: &mut ScenarioInput) -> bool {
        let mut trial = input.clone();
        let op = rand.below(nonzero!(9));
        let mutated = match op {
            0 => {
                if let Some(index) = Self::random_index(rand, trial.mmio.word_models.len()) {
                    let model = &mut trial.mmio.word_models[index];
                    if let Some(visit) = Self::random_index(rand, model.values.len()) {
                        Self::mutate_u32(rand, &mut model.values[visit]);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            1 => {
                if let Some(index) = Self::random_index(rand, trial.mmio.word_models.len()) {
                    if fits_budget(&trial, U32_BYTES) {
                        let model = &mut trial.mmio.word_models[index];
                        model.values.push(random_u32(rand));
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            2 => {
                if let Some(index) = Self::random_index(rand, trial.mmio.word_models.len()) {
                    let model = &mut trial.mmio.word_models[index];
                    if model.values.len() > 1 {
                        model.values.pop();
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            3 => {
                if let Some(index) = Self::random_index(rand, trial.dma.coherent.len()) {
                    let alloc = &mut trial.dma.coherent[index];
                    let model_index = Self::random_index(rand, alloc.word_models.len());
                    if let Some(model_index) = model_index {
                        let model = &mut alloc.word_models[model_index];
                        if let Some(visit) = Self::random_index(rand, model.values.len()) {
                            Self::mutate_u32(rand, &mut model.values[visit]);
                            true
                        } else {
                            false
                        }
                    } else if rand.below(nonzero!(2)) == 0 {
                        // Drift the alloc runtime-table index within a small range.
                        alloc.addr = rand.below(nonzero!(16)) as u64;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            4 => {
                if let Some(index) = Self::random_index(rand, trial.dma.streaming.len()) {
                    let unit = &mut trial.dma.streaming[index];
                    // Mutate one modelled visit value in ascending offset order.
                    let model_index = Self::random_index(rand, unit.word_models.len());
                    if let Some(model_index) = model_index {
                        let model = &mut unit.word_models[model_index];
                        if let Some(visit) = Self::random_index(rand, model.values.len()) {
                            Self::mutate_u32(rand, &mut model.values[visit]);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            5 => {
                if let Some(index) = Self::random_index(rand, trial.dma.streaming.len()) {
                    let unit = &mut trial.dma.streaming[index];
                    let model_index = Self::random_index(rand, unit.word_models.len());
                    if let Some(model_index) = model_index {
                        let model = &mut unit.word_models[model_index];
                        if let Some(visit) = Self::random_index(rand, model.values.len()) {
                            model.values[visit] ^= random_mask_u32(rand);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            6 => {
                // Add a unit with 1..=8 modelled words at contiguous 4-byte offsets.
                let words = 1 + rand.below(nonzero!(8));
                // Wire growth: addr(u64) + count(u32) + per word offset(u32) +
                // visit count(u32) + one u32 value.
                if fits_budget(&trial, 2 * U32_BYTES + words * (3 * U32_BYTES)) {
                    let addr = rand.below(nonzero!(16)) as u64;
                    trial.dma.streaming.push(crate::input::StreamUnit {
                        addr,
                        word_models: (0..words)
                            .map(|word| crate::input::WordModel {
                                offset: ((word * 4) as u32),
                                values: vec![random_u32(rand)],
                            })
                            .collect(),
                    });
                    true
                } else {
                    false
                }
            }
            7 => {
                if trial.dma.streaming.len() > 1 {
                    trial.dma.streaming.pop();
                    true
                } else {
                    false
                }
            }
            8 => {
                if let Some(index) = Self::random_index(rand, trial.dma.streaming.len()) {
                    // Drift the streaming unit's runtime-table index within a small range.
                    trial.dma.streaming[index].addr = rand.below(nonzero!(16)) as u64;
                    true
                } else {
                    false
                }
            }
            _ => {
                // Skeleton (the modelled slot set) is not mutated; there is no
                // whole-section rebuild op, so uncovered operation IDs are skipped.
                false
            }
        };
        if !mutated {
            return false;
        }
        if !trial.is_valid() || !fits_budget(&trial, 0) {
            return false;
        }
        if encode_scenario(&trial) == encode_scenario(input) {
            return false;
        }
        *input = trial;
        true
    }
}

/// Report `Mutated` only when the encoded byte stream actually changed and
/// the result is still a valid, in-budget scenario.
fn mutation_result(original: &[u8], input: &ScenarioInput, mutated: bool) -> MutationResult {
    if !mutated {
        return MutationResult::Skipped;
    }
    if !input.is_valid() || !fits_budget(input, 0) {
        // Treat invariant-breaking mutations as skipped; validity wins.
        return MutationResult::Skipped;
    }
    if encode_scenario(input) == original {
        MutationResult::Skipped
    } else {
        MutationResult::Mutated
    }
}

impl Named for ScenarioMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("ScenarioMutator");
        &NAME
    }
}

impl<S> Mutator<ScenarioInput, S> for ScenarioMutator
where
    S: libafl::state::HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut ScenarioInput,
    ) -> Result<MutationResult, Error> {
        let original = encode_scenario(input);
        let has_executable_rules = self
            .generator
            .sdg()
            .is_some_and(|sdg| sdg.has_executable_rules());

        if has_executable_rules {
            // Docs §5.4: a small deterministic probability performs the
            // existing random wire mutation; otherwise rule-aware semantic
            // mutation runs.
            if Self::selects_random_wire_mutation(state.rand_mut()) {
                let mutated = Self::random_wire_mutate(state.rand_mut(), input);
                return Ok(mutation_result(&original, input, mutated));
            }

            // Rule-aware path: look up the metadata recorded for these
            // exact bytes, mutate that exact semantic scenario, re-lower at
            // the stored placement, and register the child scenario for the
            // child bytes. Absent or stale metadata must never guess a
            // region or visit from the wire layout.
            let Some(scenario) = self.generator.metadata().lookup(input) else {
                return Ok(MutationResult::Skipped);
            };
            let Some(sdg) = self.generator.sdg() else {
                return Ok(MutationResult::Skipped);
            };
            return match sdg.mutate_scenario(state.rand_mut(), input, &scenario) {
                Some(child) => {
                    self.generator.metadata().register(input, child);
                    Ok(MutationResult::Mutated)
                }
                None => Ok(MutationResult::Skipped),
            };
        }

        let mutated = Self::random_wire_mutate(state.rand_mut(), input);
        Ok(mutation_result(&original, input, mutated))
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

fn random_mask_u32<R: Rand>(rand: &mut R) -> u32 {
    let lo = (rand.below(nonzero!(65536)) & 0xffff) as u32;
    let hi = (rand.below(nonzero!(65536)) & 0xffff) as u32;
    (hi << 16) | lo
}

fn random_u32<R: Rand>(rand: &mut R) -> u32 {
    let lo = (rand.below(nonzero!(65536)) & 0xffff) as u32;
    let hi = (rand.below(nonzero!(65536)) & 0xffff) as u32;
    (hi << 16) | lo
}

#[cfg(test)]
mod tests {
    use libafl::state::HasRand;
    use libafl_bolts::rands::StdRand;

    use super::*;
    use crate::input::{MmioSection, WordModel};

    #[derive(Clone, Debug)]
    struct TestState {
        rand: StdRand,
    }

    impl HasRand for TestState {
        type Rand = StdRand;

        fn rand(&self) -> &Self::Rand {
            &self.rand
        }

        fn rand_mut(&mut self) -> &mut Self::Rand {
            &mut self.rand
        }
    }

    fn parse_rule_text(text: &str) -> crate::sdg::Rule {
        crate::sdg::parse_rule_for_test(text).expect("the test rule must parse")
    }

    fn word(offset: u32, values: &[u32]) -> WordModel {
        WordModel {
            offset,
            values: values.to_vec(),
        }
    }

    fn clone_shared(generator: &ScenarioGenerator) -> ScenarioMutator {
        // A mutator cloned from the generating instance shares the metadata
        // store, so it finds the scenario recorded for the generated bytes.
        ScenarioMutator::new(generator.clone())
    }

    #[test]
    fn mutator_keeps_skeleton_and_invariants() {
        let mut state = TestState { rand: StdRand::with_seed(0) };
        let mmio_offsets = [0x110u32, 0x118, 0x11c, 0x168, 0x1b0];
        let mut input = ScenarioInput::new(
            MmioSection {
                word_models: vec![
                    word(0x110, &[1, 2]),
                    word(0x118, &[2]),
                    word(0x11c, &[1]),
                    word(0x168, &[3, 4]),
                    word(0x1b0, &[5, 6, 7]),
                ],
            },
            crate::input::DmaSection {
                streaming: vec![crate::input::StreamUnit {
                    addr: 0,
                    word_models: vec![word(0, &[1]), word(4, &[2])],
                }],
                ..Default::default()
            },
        );

        let mut mutator = ScenarioMutator::default();
        for _ in 0..64 {
            let _ = mutator.mutate(&mut state, &mut input);
            assert!(input.is_valid());
            // The modelled mmio slot set remains unchanged across mutation.
            let offsets: Vec<u32> =
                input.mmio.word_models.iter().map(|model| model.offset).collect();
            assert_eq!(offsets, mmio_offsets);
        }
    }

    #[test]
    fn mutator_targets_second_coherent_region() {
        // Two coherent allocations hold the same offset with different
        // values. The target's exact placement selects the SECOND
        // allocation, and the first allocation also satisfies the trigger,
        // so a first-wins region scan would be detectable. Only the stored
        // target region and visit may change.
        use crate::generator::ScenarioGenerator;

        let rule = parse_rule_text(
            "rule rule:dma|target:coherent:8:4:c|predicate:gt:unsigned:16\n\
             node coherent:8:4:c coherent 0x8 4\n\
             trigger coherent:8:4:c head_bound gt unsigned 16\n\
             mutation set_boundary above\n",
        );
        let sdg = crate::sdg::SemanticDependencyGraph { rules: vec![rule.clone()] };
        let generator = ScenarioGenerator::with_sdg(sdg.clone());

        // The target's exact placement: the second coherent region, visit 0.
        let mut scenario = crate::sdg::SemanticScenario {
            target_rule: rule.name.clone(),
            ..Default::default()
        };
        for node in &rule.nodes {
            scenario.insert_node(node.clone());
        }
        scenario.set("coherent:8:4:c".into(), crate::sdg::Value::U32(17));
        scenario.insert_placement("coherent:8:4:c", crate::sdg::Placement { region: 1, visit: 0 });
        let mut input = crate::sdg::lower_scenario(
            &mut scenario, &sdg.rules[0], &mut StdRand::with_seed(9),
        )
        .expect("lowering should honor the stored placement");
        assert_eq!(input.dma.coherent[0].addr, 0);
        assert_eq!(input.dma.coherent[1].addr, 1);
        assert!(input.dma.coherent[1].word_models.iter().any(|m| m.offset == 0x8));

        // The first region also satisfies the trigger at the same offset.
        input.dma.coherent[0].word_models.push(word(0x8, &[0x33]));
        assert!(input.is_valid());

        generator.metadata().register(&input, scenario);
        let mut mutator = clone_shared(&generator);

        let first_before = input.dma.coherent[0].clone();
        let mut mutated_any = false;
        for attempt in 0..64u64 {
            let mut candidate = input.clone();
            let mut state = TestState { rand: StdRand::with_seed(100 + attempt) };
            if mutator
                .mutate(&mut state, &mut candidate)
                .is_ok_and(|r| r == libafl::mutators::MutationResult::Mutated)
            {
                mutated_any = true;
                // The stored second region holds the mutated value; the
                // first region is preserved byte for byte.
                let target = &candidate.dma.coherent[1];
                let target_word = target.word_models.iter().find(|m| m.offset == 0x8)
                    .expect("the second region holds the target word");
                assert_ne!(target_word.values[0], 17, "the target visit changed");
                assert!(target_word.values[0] > 16, "the mutated value satisfies the trigger");
                assert_eq!(candidate.dma.coherent[0], first_before,
                           "a first-wins scan must never mutate the first region");
                // The registered child metadata keeps the exact placement.
                let child = generator.metadata().lookup(&candidate)
                    .expect("child metadata is registered");
                assert_eq!(
                    child.placements.get("coherent:8:4:c").copied(),
                    Some(crate::sdg::Placement { region: 1, visit: 0 }),
                    "the stored region and visit may not change"
                );
                assert_eq!(
                    child.value("coherent:8:4:c").and_then(crate::sdg::Value::as_u64),
                    Some(u64::from(target_word.values[0])),
                );
                break;
            }
        }
        assert!(mutated_any, "the scenario mutator should apply");
    }

    #[test]
    fn mutator_targets_second_streaming_region() {
        // Two streaming units hold the same offset with different values.
        // The target's exact placement selects the SECOND unit and the
        // first unit also satisfies the trigger, so a first-wins region
        // scan would be detectable. Only the stored target region may
        // change.
        use crate::generator::ScenarioGenerator;
        use crate::input::StreamUnit;

        let rule = parse_rule_text(
            "rule rule:stream|target:streaming:0:8:4:payload_word|predicate:gt:unsigned:16\n\
             node streaming:0:8:4:payload_word streaming 0 0x8 4\n\
             trigger streaming:0:8:4:payload_word head_bound gt unsigned 16\n\
             mutation set_boundary above\n",
        );
        let sdg = crate::sdg::SemanticDependencyGraph { rules: vec![rule.clone()] };
        let generator = ScenarioGenerator::with_sdg(sdg.clone());

        // The target's exact placement: the second streaming unit, visit 0.
        let mut scenario = crate::sdg::SemanticScenario {
            target_rule: rule.name.clone(),
            ..Default::default()
        };
        for node in &rule.nodes {
            scenario.insert_node(node.clone());
        }
        scenario.set("streaming:0:8:4:payload_word".into(), crate::sdg::Value::U32(17));
        // The protocol slot maps to the second runtime region.
        scenario.slot_regions.insert(0, 1);
        scenario.insert_placement(
            "streaming:0:8:4:payload_word",
            crate::sdg::Placement { region: 1, visit: 0 },
        );
        let mut input = crate::sdg::lower_scenario(
            &mut scenario, &sdg.rules[0], &mut StdRand::with_seed(9),
        )
        .expect("lowering should honor the stored placement");
        assert_eq!(input.dma.streaming.len(), 1);
        assert_eq!(input.dma.streaming[0].addr, 1);

        // The first streaming region also satisfies the trigger at the
        // same offset.
        input.dma.streaming.insert(
            0,
            StreamUnit { addr: 0, word_models: vec![word(0x8, &[0x33])] },
        );
        assert!(input.is_valid());

        generator.metadata().register(&input, scenario);
        let mut mutator = clone_shared(&generator);

        let first_before = input.dma.streaming[0].clone();
        let mut mutated_any = false;
        for attempt in 0..64u64 {
            let mut candidate = input.clone();
            let mut state = TestState { rand: StdRand::with_seed(200 + attempt) };
            if mutator
                .mutate(&mut state, &mut candidate)
                .is_ok_and(|r| r == libafl::mutators::MutationResult::Mutated)
            {
                mutated_any = true;
                // The stored second unit holds the mutated value; the first
                // unit is preserved byte for byte.
                let target = candidate.dma.streaming.iter().find(|u| u.addr == 1)
                    .expect("the second unit survives");
                let target_word = target.word_models.iter().find(|m| m.offset == 0x8)
                    .expect("the second unit holds the target word");
                assert_ne!(target_word.values[0], 17, "the target visit changed");
                assert!(target_word.values[0] > 16, "the mutated value satisfies the trigger");
                assert_eq!(candidate.dma.streaming[0], first_before,
                           "a first-wins scan must never mutate the first unit");
                // The registered child metadata keeps the exact placement.
                let child = generator.metadata().lookup(&candidate)
                    .expect("child metadata is registered");
                assert_eq!(
                    child.placements.get("streaming:0:8:4:payload_word").copied(),
                    Some(crate::sdg::Placement { region: 1, visit: 0 }),
                    "the stored region and visit may not change"
                );
                break;
            }
        }
        assert!(mutated_any, "the scenario mutator should apply");
    }

    #[test]
    fn mutator_updates_nonfinal_visit_with_opposite_insertion_order() {
        // Two same-word mmio fields. The target's canonical id sorts before
        // the precondition variable's, so generation inserts the target
        // last: insertion order is opposite canonical order. The target
        // sits on a non-final visit of the word model, and exact placement
        // metadata must make the Mutator trait path update only the
        // original target visit.
        use crate::generator::ScenarioGenerator;
        use libafl::generators::Generator;

        let rule = parse_rule_text(
            "rule rule:order|target:mmio:256:1:a|predicate:gt:unsigned:40\n\
             node mmio:256:1:a mmio 0x100 1\n\
             node mmio:257:1:b mmio 0x101 1\n\
             precondition mmio:257:1:b mmio:256:1:a head_guard bit_set 1\n\
             trigger mmio:256:1:a head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        );
        let sdg = crate::sdg::SemanticDependencyGraph { rules: vec![rule] };
        let mut generator = ScenarioGenerator::with_sdg(sdg.clone());

        // Find a generation whose target sits on a non-final visit that the
        // other field does not share.
        let mut found = None;
        for seed in 0..64u64 {
            let mut state = TestState { rand: StdRand::with_seed(seed) };
            let input = generator
                .generate(&mut state)
                .expect("generation should satisfy the rule");
            let scenario = generator.metadata().lookup(&input)
                .expect("generation registers metadata");
            let model = &input.mmio.word_models[0];
            let target_visit = scenario.placements.get("mmio:256:1:a").unwrap().visit;
            let other_visit = scenario.placements.get("mmio:257:1:b").unwrap().visit;
            if target_visit + 1 < model.values.len() && other_visit != target_visit {
                found = Some((input, target_visit));
                break;
            }
        }
        let (input, target_visit) = found
            .expect("some fixed seed places the target on a non-final visit");
        let before: Vec<u32> = input.mmio.word_models[0].values.clone();
        let mut mutator = clone_shared(&generator);

        let mut mutated_any = false;
        for attempt in 0..64u64 {
            let mut candidate = input.clone();
            let mut state = TestState { rand: StdRand::with_seed(1000 + attempt) };
            if !mutator
                .mutate(&mut state, &mut candidate)
                .is_ok_and(|r| r == libafl::mutators::MutationResult::Mutated)
            {
                continue;
            }
            let Some(child) = generator.metadata().lookup(&candidate) else {
                // The random wire branch fabricated no metadata; keep looking.
                continue;
            };
            mutated_any = true;
            let model = &candidate.mmio.word_models[0];
            for (visit, (word, original)) in
                model.values.iter().zip(before.iter()).enumerate()
            {
                if visit == target_visit {
                    // The target's own byte changed; the rest of the visit
                    // word is preserved.
                    assert_ne!(word & 0xff, original & 0xff, "the original target visit changed");
                    assert!(word & 0xff > 40, "the mutated target satisfies the trigger");
                    assert_eq!(word & !0xff, original & !0xff,
                               "other bytes in the target visit are preserved");
                } else {
                    assert_eq!(word, original, "every other visit byte is preserved");
                }
            }
            // The child metadata keeps the original visit: only the value
            // moved.
            assert_eq!(
                child.placements.get("mmio:256:1:a").copied(),
                Some(crate::sdg::Placement { region: 0, visit: target_visit }),
                "the original visit is preserved in the child metadata"
            );
            break;
        }
        assert!(mutated_any, "the scenario mutator should apply");
    }

    #[test]
    fn mutator_reaches_both_documented_fallback_branches() {
        // Docs §5.4: with a non-empty SDG, a small deterministic
        // probability performs the existing random wire mutation; otherwise
        // rule-aware semantic mutation runs. With fixed seeds both branches
        // must be reached, and a rule-aware child registers metadata while
        // a random wire child does not.
        use crate::generator::ScenarioGenerator;
        use libafl::generators::Generator;

        let rule = parse_rule_text(
            "rule rule:branch|target:mmio:256:1:x|predicate:gt:unsigned:40\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        );
        let sdg = crate::sdg::SemanticDependencyGraph { rules: vec![rule] };
        let mut generator = ScenarioGenerator::with_sdg(sdg);
        let mut state = TestState { rand: StdRand::with_seed(0) };
        let input = generator
            .generate(&mut state)
            .expect("generation should satisfy the rule");
        let mut mutator = clone_shared(&generator);

        let mut rule_aware_mutated = false;
        let mut random_wire_mutated = false;
        for seed in 0..256u64 {
            let mut candidate = input.clone();
            let mut state = TestState { rand: StdRand::with_seed(seed) };
            if !mutator
                .mutate(&mut state, &mut candidate)
                .is_ok_and(|r| r == libafl::mutators::MutationResult::Mutated)
            {
                continue;
            }
            if generator.metadata().lookup(&candidate).is_some() {
                // The rule-aware branch registered the child scenario.
                rule_aware_mutated = true;
            } else {
                // The random wire branch fabricates no semantic metadata.
                random_wire_mutated = true;
            }
        }
        assert!(rule_aware_mutated, "the rule-aware branch must be reached with fixed seeds");
        assert!(random_wire_mutated, "the random wire branch must be reached with fixed seeds");
    }

    #[test]
    fn mutator_skips_wire_only_seeds_without_metadata() {
        // Imported/foreign wire-format seeds have no metadata; the
        // rule-aware path must return Skipped and never guess a region or
        // visit. Only the documented random wire branch may mutate them.
        use crate::generator::ScenarioGenerator;

        let rule = parse_rule_text(
            "rule rule:solo|target:mmio:256:1:x|predicate:gt:unsigned:40\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        );
        let sdg = crate::sdg::SemanticDependencyGraph { rules: vec![rule] };
        let generator = ScenarioGenerator::with_sdg(sdg);
        let mut mutator = ScenarioMutator::new(generator);

        // A wire-format seed whose word model happens to hold a value that
        // satisfies the trigger: without metadata this must never be
        // rule-aware mutated.
        let input = ScenarioInput::new(
            MmioSection { word_models: vec![word(0x100, &[41])] },
            crate::input::DmaSection::default(),
        );
        for seed in 0..64u64 {
            let mut state = TestState { rand: StdRand::with_seed(seed) };
            let mut candidate = input.clone();
            let result = mutator.mutate(&mut state, &mut candidate).unwrap();
            let random_branch = {
                let mut probe = StdRand::with_seed(seed);
                ScenarioMutator::selects_random_wire_mutation(&mut probe)
            };
            if !random_branch {
                assert_eq!(result, libafl::mutators::MutationResult::Skipped,
                           "wire-only seeds must never be rule-aware mutated");
                assert_eq!(candidate, input, "an unmutated seed keeps its bytes");
            }
        }
    }

    #[test]
    fn mutator_rejects_stale_metadata_after_byte_changes() {
        // Metadata registered for one exact byte block must not guide
        // mutation of changed bytes: the lookup is keyed to the exact
        // digest, and stale metadata is rejected instead of applied.
        use crate::generator::ScenarioGenerator;
        use libafl::generators::Generator;

        let rule = parse_rule_text(
            "rule rule:stale|target:mmio:256:1:x|predicate:gt:unsigned:40\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        );
        let sdg = crate::sdg::SemanticDependencyGraph { rules: vec![rule] };
        let mut generator = ScenarioGenerator::with_sdg(sdg);
        let mut state = TestState { rand: StdRand::with_seed(0) };
        let mut input = generator
            .generate(&mut state)
            .expect("generation should satisfy the rule");
        assert!(generator.metadata().lookup(&input).is_some());

        // Change the bytes: the recorded metadata is now stale.
        input.mmio.word_models[0].values[0] ^= 1;
        assert!(generator.metadata().lookup(&input).is_none(),
                "changed bytes must not find the parent metadata");

        let mut mutator = clone_shared(&generator);
        for seed in 0..64u64 {
            let mut state = TestState { rand: StdRand::with_seed(seed) };
            let random_branch = {
                let mut probe = StdRand::with_seed(seed);
                ScenarioMutator::selects_random_wire_mutation(&mut probe)
            };
            if !random_branch {
                let mut candidate = input.clone();
                assert_eq!(
                    mutator.mutate(&mut state, &mut candidate).unwrap(),
                    libafl::mutators::MutationResult::Skipped,
                    "stale metadata must be rejected, never applied"
                );
            }
        }
    }

    #[test]
    fn mutator_never_exceeds_the_encoded_budget() {
        use crate::encoding::encode_scenario;

        let mut state = TestState { rand: StdRand::with_seed(7) };
        // One streaming unit encodes to addr(8) + count(4) + num * (offset(4) +
        // visit count(4) + one value(4)); empty mmio/coherent sections add 8.
        let start_len = {
            let words = (MAX_ENCODED_SCENARIO_BYTES - 20) / (3 * U32_BYTES);
            assert_eq!(20 + words * (3 * U32_BYTES), MAX_ENCODED_SCENARIO_BYTES - 8);
            MAX_ENCODED_SCENARIO_BYTES - 8
        };
        let streaming_words = (start_len - 20) / (3 * U32_BYTES);
        let mut input = ScenarioInput::new(
            MmioSection::default(),
            crate::input::DmaSection {
                streaming: vec![crate::input::StreamUnit {
                    addr: 0,
                    word_models: (0..streaming_words)
                        .map(|w| word((w * 4) as u32, &[1]))
                        .collect(),
                }],
                ..Default::default()
            },
        );
        assert_eq!(encode_scenario(&input).len(), start_len);

        let mut mutator = ScenarioMutator::default();
        for _ in 0..256 {
            let _ = mutator.mutate(&mut state, &mut input);
            assert!(
                encode_scenario(&input).len() <= MAX_ENCODED_SCENARIO_BYTES,
                "mutated input {} exceeds the stub cap {}",
                encode_scenario(&input).len(),
                MAX_ENCODED_SCENARIO_BYTES
            );
        }
    }

    #[test]
    fn skipped_random_mutation_leaves_input_byte_for_byte_unchanged() {
        // The random wire mutation runs on a clone and commits only for a
        // mutated, valid, in-budget result: a skipped mutation must leave
        // the input byte-for-byte unchanged.
        use crate::encoding::encode_scenario;

        let mut input = ScenarioInput::new(
            MmioSection {
                word_models: vec![
                    word(0x110, &[1]),
                    word(0x118, &[2]),
                ],
            },
            crate::input::DmaSection {
                streaming: vec![crate::input::StreamUnit {
                    addr: 0,
                    word_models: vec![word(0, &[1])],
                }],
                ..Default::default()
            },
        );
        let mut mutator = ScenarioMutator::default();
        let mut mutated_count = 0usize;
        let mut skipped_count = 0usize;
        for seed in 0..256u64 {
            let before = encode_scenario(&input);
            let mut state = TestState { rand: StdRand::with_seed(seed) };
            match mutator.mutate(&mut state, &mut input).unwrap() {
                libafl::mutators::MutationResult::Mutated => {
                    mutated_count += 1;
                    let after = encode_scenario(&input);
                    assert_ne!(after, before, "a mutated result must differ");
                }
                libafl::mutators::MutationResult::Skipped => {
                    skipped_count += 1;
                    let after = encode_scenario(&input);
                    assert_eq!(after, before, "a skipped mutation leaves the input unchanged");
                }
            }
            assert!(input.is_valid());
        }
        assert!(mutated_count > 0, "some seeds should mutate");
        assert!(skipped_count > 0, "some seeds should skip");
        assert!(encode_scenario(&input).len() <= MAX_ENCODED_SCENARIO_BYTES);
    }

    #[test]
    fn generator_seed_sidecar_and_fresh_restart_rule_aware_mutates() {
        // The real corpus lifecycle: the generator persists the semantic
        // sidecar next to an on-disk seed file; a fresh generator and
        // mutator (a restarted process) load the seed from disk and find
        // the sidecar record for the exact bytes, so rule-aware mutation
        // applies without any wire-layout guessing.
        use crate::generator::ScenarioGenerator;
        use libafl::generators::Generator;
        use libafl::inputs::Input;
        use std::time::{SystemTime, UNIX_EPOCH};

        let rule = parse_rule_text(
            "rule rule:restart|target:mmio:256:1:x|predicate:gt:unsigned:40\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        );
        let sdg = crate::sdg::SemanticDependencyGraph { rules: vec![rule] };
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sdg-restart-{}-{nonce}",
            std::process::id()
        ));
        let sidecar = dir.join("corpus.sdg-metadata");

        // First process: generate, persist the sidecar, store the seed file.
        let mut first_generator =
            ScenarioGenerator::with_sdg(sdg.clone()).with_metadata_dir(&sidecar);
        let mut state = TestState { rand: StdRand::with_seed(0) };
        let input = first_generator
            .generate(&mut state)
            .expect("generation should satisfy the rule");
        assert!(
            first_generator.metadata().lookup(&input).is_some(),
            "generation registers metadata"
        );
        let seed_file = dir.join("seed-0.bin");
        input.to_file(&seed_file).expect("the seed should be stored");
        let digest = crate::metadata::ScenarioMetadataStore::hex_digest(
            &crate::metadata::ScenarioMetadataStore::digest_of_input(&input),
        );
        assert!(sidecar.join(format!("{digest}.json")).is_file());

        // Second process: a fresh store, generator, and mutator; the corpus
        // seed is loaded from disk and the sidecar is lazy-loaded.
        let restarted_generator = ScenarioGenerator::with_sdg(sdg.clone()).with_metadata_dir(&sidecar);
        let mut mutator = ScenarioMutator::new(restarted_generator.clone());
        let loaded = ScenarioInput::from_file(&seed_file).expect("the seed file should decode");
        assert_eq!(loaded, input);
        let mut mutated_any = false;
        for attempt in 0..64u64 {
            let mut candidate = loaded.clone();
            let mut state = TestState { rand: StdRand::with_seed(attempt) };
            let random_branch = {
                let mut probe = StdRand::with_seed(attempt);
                ScenarioMutator::selects_random_wire_mutation(&mut probe)
            };
            if random_branch {
                continue;
            }
            if mutator
                .mutate(&mut state, &mut candidate)
                .is_ok_and(|r| r == libafl::mutators::MutationResult::Mutated)
            {
                mutated_any = true;
                // The child metadata is registered for the child bytes in
                // the restarted store and persisted to the shared sidecar.
                let child = restarted_generator
                    .metadata()
                    .lookup(&candidate)
                    .expect("the mutator registers and persists the child metadata");
                let child_digest = crate::metadata::ScenarioMetadataStore::hex_digest(
                    &crate::metadata::ScenarioMetadataStore::digest_of_input(&candidate),
                );
                assert!(sidecar.join(format!("{child_digest}.json")).is_file());
                let x = child
                    .value("mmio:256:1:x")
                    .and_then(crate::sdg::Value::as_u64)
                    .expect("the target variable survives");
                assert!(x > 40, "the target state holds after mutation: {x}");
                break;
            }
        }
        assert!(mutated_any, "the restarted process must rule-aware mutate");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn persistent_store_foreign_seed_still_falls_back() {
        // A foreign seed without a sidecar record must never be rule-aware
        // mutated, even when the store has a persistent sidecar with other
        // records.
        use crate::generator::ScenarioGenerator;

        let rule = parse_rule_text(
            "rule rule:foreign|target:mmio:256:1:x|predicate:gt:unsigned:40\n\
             node mmio:256:1:x mmio 0x100 1\n\
             trigger mmio:256:1:x head_bound gt unsigned 40\n\
             mutation set_boundary above\n",
        );
        let sdg = crate::sdg::SemanticDependencyGraph { rules: vec![rule] };
        let dir = std::env::temp_dir().join(format!(
            "sdg-foreign-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let generator = ScenarioGenerator::with_sdg(sdg).with_metadata_dir(&dir);
        let mut mutator = ScenarioMutator::new(generator);

        // A foreign wire-format seed holding a satisfying value.
        let input = ScenarioInput::new(
            MmioSection { word_models: vec![word(0x100, &[41])] },
            crate::input::DmaSection::default(),
        );
        for seed in 0..64u64 {
            let mut state = TestState { rand: StdRand::with_seed(seed) };
            let mut candidate = input.clone();
            let random_branch = {
                let mut probe = StdRand::with_seed(seed);
                ScenarioMutator::selects_random_wire_mutation(&mut probe)
            };
            if !random_branch {
                assert_eq!(
                    mutator.mutate(&mut state, &mut candidate).unwrap(),
                    libafl::mutators::MutationResult::Skipped,
                    "foreign seeds without a sidecar must not be rule-aware mutated"
                );
                assert_eq!(candidate, input, "an unmutated seed keeps its bytes");
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
