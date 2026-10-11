extern crate alloc;
use libafl::{generators::Generator, mutators::{MutationResult, Mutator}, state::HasRand};
use libafl_bolts::rands::StdRand;
use sdg::{SemanticDependencyGraph, lift_with, lower_scenario};

struct State { random: StdRand }
impl HasRand for State {
    type Rand = StdRand;
    fn rand(&self) -> &StdRand { &self.random }
    fn rand_mut(&mut self) -> &mut StdRand { &mut self.random }
}

fn check_wire(input: &input::ScenarioInput) {
    assert!(input.is_valid());
    let bytes = encoding::encode_scenario(input);
    assert!(bytes.len() <= input::MAX_ENCODED_SCENARIO_BYTES);
    assert_eq!(encoding::decode_scenario(&bytes).expect("decode wire bytes"), *input);
}

fn main() {
    let directory = std::env::args().nth(1).expect("rule directory");
    // SAFETY: the checker configures its environment before starting any threads.
    unsafe {
        std::env::set_var("MORPHEUS_LIBAFL_SDG_RULES", &directory);
        std::env::remove_var("MORPHEUS_LIBAFL_DISABLE_SDG");
    }
    let mut generator = generator::ScenarioGenerator::from_env().expect("load semantic rules");
    let graph = generator.sdg().expect("configured rule directory").clone();
    eprintln!("Loaded {} rules; checking generation, mutation and wire round trips", graph.rules.len());
    let mut executable = 0;
    let mut blocked = 0;
    let mut generated = 0;
    let mut mutated = 0;
    let mut reasons = std::collections::BTreeMap::new();
    let mut documents_checked = 0;
    for (index, rule) in graph.rules.iter().enumerate() {
        if index % 100 == 0 { eprintln!("Checked {index}/{} rules", graph.rules.len()); }
        // Sample lossless evidence restoration as well as every runtime plan.
        if documents_checked < 3 {
            if let Some(semantic) = &rule.semantic {
                let document = semantic.document.read().expect("restore semantic evidence");
                let restored = sdg::semantic::parse(&document).expect("parse restored evidence");
                assert_eq!(restored.name, rule.name);
                assert_eq!(restored.nodes, rule.nodes);
                assert_eq!(restored.runtime_blockers().len(), rule.runtime_blockers().len());
                if rule.runtime_blockers().is_empty() {
                    for seed in 0..4 {
                        let actual = sdg::semantic::generate(rule, &mut StdRand::with_seed(seed)).unwrap();
                        let expected = sdg::semantic::generate(&restored, &mut StdRand::with_seed(seed)).unwrap();
                        assert_eq!(actual.values, expected.values);
                        assert_eq!(actual.placements, expected.placements);
                    }
                }
                documents_checked += 1;
            }
        }
        if !rule.runtime_blockers().is_empty() {
            blocked += 1;
            for blocker in rule.runtime_blockers() { *reasons.entry(blocker.reason.clone()).or_insert(0usize) += 1; }
            continue;
        }
        executable += 1;
        let single = SemanticDependencyGraph { rules: vec![rule.clone()] };
        for seed in 0..8 {
            let mut rand = StdRand::with_seed(seed);
            let mut scenario = single.generate(&mut rand).unwrap_or_else(|e|panic!("{}: {e}",rule.name));
            let mut input = lower_scenario(&mut scenario, rule, &mut rand).expect("lower semantic sources");
            check_wire(&input);
            let lifted = lift_with(&input, rule, &scenario.placements).expect("lift exact source placements");
            assert_eq!(scenario.values, lifted.values, "{}", rule.name);
            generated += 1;
            if let Some(child) = single.mutate_scenario(&mut rand, &mut input, &scenario) {
                let lifted = lift_with(&input, rule, &child.placements).expect("lift mutated sources");
                assert_eq!(child.values,lifted.values,"{}",rule.name);
                assert_ne!(scenario.values,child.values);
                check_wire(&input);
                mutated += 1;
            }
        }
    }
    let mut integration_generated = 0;
    let mut integration_mutated = 0;
    let mut mutator = mutator::ScenarioMutator::new(generator.clone());
    for seed in 0..32 {
        let mut state = State { random: StdRand::with_seed(seed) };
        let mut input = generator.generate(&mut state).expect("ScenarioGenerator generation");
        check_wire(&input);
        if graph.has_executable_rules() {
            let parent = generator.metadata().lookup(&input).expect("generated semantic metadata");
            let rule = graph.rules.iter().find(|r| r.name == parent.target_rule).unwrap();
            assert_eq!(lift_with(&input, rule, &parent.placements).unwrap().values, parent.values);
            if mutator.mutate(&mut state, &mut input).unwrap() == MutationResult::Mutated {
                check_wire(&input);
                if let Some(child) = generator.metadata().lookup(&input) {
                    assert_eq!(child.placements, parent.placements);
                    assert_eq!(lift_with(&input, rule, &child.placements).unwrap().values, child.values);
                    integration_mutated += 1;
                }
            }
        } else {
            assert!(generator.metadata().lookup(&input).is_none());
            mutator.mutate(&mut state, &mut input).expect("fallback mutation");
            check_wire(&input);
        }
        integration_generated += 1;
    }
    println!("{}",serde_json::json!({"loaded":graph.rules.len(),"executable":executable,
        "requires_binding_or_irq_only":blocked,"generated":generated,"mutated":mutated,"reasons":reasons,
        "integration_generated":integration_generated,"integration_mutated":integration_mutated,
        "documents_checked":documents_checked}));
    assert!(!graph.rules.is_empty());
}
