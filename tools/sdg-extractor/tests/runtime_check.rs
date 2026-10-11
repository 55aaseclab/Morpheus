extern crate alloc;

use libafl_bolts::rands::StdRand;
use sdg::{SemanticDependencyGraph, lift_with, lower_scenario};

fn main() {
    let directory = std::env::args().nth(1).expect("rule directory");
    let graph = SemanticDependencyGraph::from_dir(std::path::Path::new(&directory))
        .expect("runtime rejected exported rules");
    assert!(!graph.rules.is_empty(), "no exported rules to test");
    for rule in &graph.rules {
        let single = SemanticDependencyGraph { rules: vec![rule.clone()] };
        for seed in 0..32 {
            let mut random = StdRand::with_seed(seed);
            let mut scenario = single.generate(&mut random).expect("generation failed");
            let mut input = lower_scenario(&mut scenario, rule, &mut random)
                .expect("lowering failed");
            let lifted = lift_with(&input, rule, &scenario.placements).expect("lifting failed");
            assert_eq!(scenario.values, lifted.values);
            for condition in rule.preconditions.iter().chain(std::iter::once(&rule.trigger)) {
                let node = rule.node_for(condition.predicate_var()).expect("missing node");
                let value = lifted.value(&node.name).and_then(|value| value.as_u64())
                    .expect("missing value");
                assert!(condition.predicate.satisfied_by(value, node.width_bits));
            }
            let target = rule.target_var();
            let node = rule.node_for(target).expect("missing target");
            let expected = scenario.value(target).and_then(|value| value.as_u64()).unwrap();
            scenario.set(target.to_owned(), sdg::Value::from_u64(expected ^ 1, node.width_bits).unwrap());
            input = lower_scenario(&mut scenario, rule, &mut random).expect("lowering parent failed");
            let mutated = single.mutate_scenario(&mut random, &mut input, &scenario)
                .unwrap_or_else(|| panic!("mutation failed: {} seed {}", rule.name, seed));
            assert_eq!(mutated.value(target).and_then(|value| value.as_u64()), Some(expected));
        }
    }
    println!("Validated {} rules with the runtime parser, generator, lowering, and mutation (32 seeds each)",
             graph.rules.len());
}
