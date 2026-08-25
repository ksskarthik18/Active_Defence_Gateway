use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct WmmfFlowRequest {
    pub flow_id: String,
    pub weight: f64,
    pub demand: f64,
    pub min_guarantee: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WmmfAllocation {
    pub flow_id: String,
    pub allocated_capacity: f64,
}

pub struct WeightedMaxMinFairness;

impl WeightedMaxMinFairness {
    /// Computes Weighted Max-Min Fair capacity allocation across flows.
    ///
    /// 1. Satisfies minimum guarantees for all flows (up to total capacity).
    /// 2. Distributes remaining capacity proportionally to flow weights.
    /// 3. If a flow's allocation exceeds its demand, caps allocation to demand and redistributes surplus iteratively.
    pub fn allocate(total_capacity: f64, flows: &[WmmfFlowRequest]) -> Vec<WmmfAllocation> {
        if total_capacity <= 0.0 || flows.is_empty() {
            return flows
                .iter()
                .map(|f| WmmfAllocation {
                    flow_id: f.flow_id.clone(),
                    allocated_capacity: 0.0,
                })
                .collect();
        }

        let mut alloc_map: BTreeMap<String, f64> = BTreeMap::new();
        let mut active: BTreeMap<String, &WmmfFlowRequest> = BTreeMap::new();

        let mut rem_cap = total_capacity;

        // Step 1: Assign min guarantee (capped at demand)
        for f in flows {
            let initial_min = f.min_guarantee.min(f.demand).max(0.0);
            let granted_min = initial_min.min(rem_cap);
            rem_cap -= granted_min;
            alloc_map.insert(f.flow_id.clone(), granted_min);

            if granted_min < f.demand {
                active.insert(f.flow_id.clone(), f);
            }
        }

        // Step 2 & 3: Water-filling loop for remaining capacity
        while rem_cap > 1e-6 && !active.is_empty() {
            let total_active_weight: f64 = active.values().map(|f| f.weight.max(0.001)).sum();
            if total_active_weight <= 0.0 {
                break;
            }

            let mut any_saturated = false;
            let current_rem_cap = rem_cap;

            // Check if any flow hits its demand ceiling under proportional share
            for (&ref id, f) in active.clone().iter() {
                let share = current_rem_cap * (f.weight.max(0.001) / total_active_weight);
                let current_alloc = alloc_map.get(id).cloned().unwrap_or(0.0);
                let additional_needed = f.demand - current_alloc;

                if share >= additional_needed {
                    // Saturated!
                    let final_alloc = f.demand;
                    rem_cap -= additional_needed;
                    alloc_map.insert(id.clone(), final_alloc);
                    active.remove(id);
                    any_saturated = true;
                }
            }

            // If no flow saturated in this pass, allocate proportionally to all active flows and finish
            if !any_saturated {
                for (id, f) in active.iter() {
                    let share = rem_cap * (f.weight.max(0.001) / total_active_weight);
                    let current_alloc = alloc_map.get(id).cloned().unwrap_or(0.0);
                    alloc_map.insert(id.clone(), current_alloc + share);
                }
                break;
            }
        }

        // Preserve input order
        flows
            .iter()
            .map(|f| WmmfAllocation {
                flow_id: f.flow_id.clone(),
                allocated_capacity: *alloc_map.get(&f.flow_id).unwrap_or(&0.0),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equal_weights() {
        let flows = vec![
            WmmfFlowRequest { flow_id: "A".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 0.0 },
            WmmfFlowRequest { flow_id: "B".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 0.0 },
            WmmfFlowRequest { flow_id: "C".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 0.0 },
        ];

        let allocs = WeightedMaxMinFairness::allocate(90.0, &flows);
        assert_eq!(allocs[0].allocated_capacity, 30.0);
        assert_eq!(allocs[1].allocated_capacity, 30.0);
        assert_eq!(allocs[2].allocated_capacity, 30.0);
    }

    #[test]
    fn test_unequal_weights_1_2_3() {
        let flows = vec![
            WmmfFlowRequest { flow_id: "A".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 0.0 },
            WmmfFlowRequest { flow_id: "B".to_string(), weight: 2.0, demand: 100.0, min_guarantee: 0.0 },
            WmmfFlowRequest { flow_id: "C".to_string(), weight: 3.0, demand: 100.0, min_guarantee: 0.0 },
        ];

        let allocs = WeightedMaxMinFairness::allocate(100.0, &flows);
        // A gets 1/6 = 16.666..., B gets 2/6 = 33.333..., C gets 3/6 = 50.0
        assert!((allocs[0].allocated_capacity - 16.6666).abs() < 0.01);
        assert!((allocs[1].allocated_capacity - 33.3333).abs() < 0.01);
        assert!((allocs[2].allocated_capacity - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_saturated_flows_and_redistribution() {
        let flows = vec![
            WmmfFlowRequest { flow_id: "A".to_string(), weight: 1.0, demand: 10.0, min_guarantee: 0.0 }, // Capped at 10
            WmmfFlowRequest { flow_id: "B".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 0.0 },
            WmmfFlowRequest { flow_id: "C".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 0.0 },
        ];

        let allocs = WeightedMaxMinFairness::allocate(100.0, &flows);
        // A capped at 10. Remaining 90 split equally between B and C -> 45 each.
        assert_eq!(allocs[0].allocated_capacity, 10.0);
        assert_eq!(allocs[1].allocated_capacity, 45.0);
        assert_eq!(allocs[2].allocated_capacity, 45.0);
    }

    #[test]
    fn test_minimum_guarantees() {
        let flows = vec![
            WmmfFlowRequest { flow_id: "A".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 40.0 },
            WmmfFlowRequest { flow_id: "B".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 0.0 },
        ];

        let allocs = WeightedMaxMinFairness::allocate(60.0, &flows);
        // A gets 40 min guarantee. Remaining 20 split equally -> A gets 40+10=50, B gets 10.
        assert_eq!(allocs[0].allocated_capacity, 50.0);
        assert_eq!(allocs[1].allocated_capacity, 10.0);
    }

    #[test]
    fn test_unused_demand() {
        let flows = vec![
            WmmfFlowRequest { flow_id: "A".to_string(), weight: 1.0, demand: 5.0, min_guarantee: 0.0 },
        ];
        let allocs = WeightedMaxMinFairness::allocate(100.0, &flows);
        assert_eq!(allocs[0].allocated_capacity, 5.0);
    }

    #[test]
    fn test_zero_capacity() {
        let flows = vec![
            WmmfFlowRequest { flow_id: "A".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 10.0 },
        ];
        let allocs = WeightedMaxMinFairness::allocate(0.0, &flows);
        assert_eq!(allocs[0].allocated_capacity, 0.0);
    }

    // ===== BRUTAL EDGE CASES =====

    #[test]
    fn test_empty_flows() {
        let flows: Vec<WmmfFlowRequest> = vec![];
        let allocs = WeightedMaxMinFairness::allocate(100.0, &flows);
        assert!(allocs.is_empty());
    }

    #[test]
    fn test_single_flow_gets_full_capacity() {
        let flows = vec![
            WmmfFlowRequest { flow_id: "A".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 0.0 },
        ];
        let allocs = WeightedMaxMinFairness::allocate(100.0, &flows);
        assert_eq!(allocs[0].allocated_capacity, 100.0);
    }

    #[test]
    fn test_all_flows_saturated_well_below_capacity() {
        let flows = vec![
            WmmfFlowRequest { flow_id: "A".to_string(), weight: 1.0, demand: 5.0, min_guarantee: 0.0 },
            WmmfFlowRequest { flow_id: "B".to_string(), weight: 1.0, demand: 10.0, min_guarantee: 0.0 },
            WmmfFlowRequest { flow_id: "C".to_string(), weight: 1.0, demand: 15.0, min_guarantee: 0.0 },
        ];
        let allocs = WeightedMaxMinFairness::allocate(1000.0, &flows);
        // All capped at demand
        assert_eq!(allocs[0].allocated_capacity, 5.0);
        assert_eq!(allocs[1].allocated_capacity, 10.0);
        assert_eq!(allocs[2].allocated_capacity, 15.0);
    }

    #[test]
    fn test_guarantees_exceed_capacity() {
        let flows = vec![
            WmmfFlowRequest { flow_id: "A".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 80.0 },
            WmmfFlowRequest { flow_id: "B".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 80.0 },
        ];
        let allocs = WeightedMaxMinFairness::allocate(100.0, &flows);
        // Total guarantees = 160 but capacity = 100
        // A gets 80, B gets remaining 20
        let total: f64 = allocs.iter().map(|a| a.allocated_capacity).sum();
        assert!(total <= 100.0 + 1e-6, "Total allocation must not exceed capacity");
    }

    #[test]
    fn test_cascading_saturation() {
        // A demands 5, B demands 20, C demands 100, total capacity 100
        // Equal weights: proportional = 33.3 each
        // A saturates at 5, surplus 28.3 redistributed
        // B gets ~20, C gets rest
        let flows = vec![
            WmmfFlowRequest { flow_id: "A".to_string(), weight: 1.0, demand: 5.0, min_guarantee: 0.0 },
            WmmfFlowRequest { flow_id: "B".to_string(), weight: 1.0, demand: 20.0, min_guarantee: 0.0 },
            WmmfFlowRequest { flow_id: "C".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 0.0 },
        ];
        let allocs = WeightedMaxMinFairness::allocate(100.0, &flows);
        assert_eq!(allocs[0].allocated_capacity, 5.0);
        assert_eq!(allocs[1].allocated_capacity, 20.0);
        assert_eq!(allocs[2].allocated_capacity, 75.0); // remainder
    }

    #[test]
    fn test_output_order_matches_input_order() {
        let flows = vec![
            WmmfFlowRequest { flow_id: "Z".to_string(), weight: 3.0, demand: 100.0, min_guarantee: 0.0 },
            WmmfFlowRequest { flow_id: "A".to_string(), weight: 1.0, demand: 100.0, min_guarantee: 0.0 },
            WmmfFlowRequest { flow_id: "M".to_string(), weight: 2.0, demand: 100.0, min_guarantee: 0.0 },
        ];
        let allocs = WeightedMaxMinFairness::allocate(60.0, &flows);
        assert_eq!(allocs[0].flow_id, "Z");
        assert_eq!(allocs[1].flow_id, "A");
        assert_eq!(allocs[2].flow_id, "M");
    }

    #[test]
    fn test_negative_capacity_treated_as_zero() {
        let flows = vec![
            WmmfFlowRequest { flow_id: "A".to_string(), weight: 1.0, demand: 50.0, min_guarantee: 0.0 },
        ];
        let allocs = WeightedMaxMinFairness::allocate(-10.0, &flows);
        assert_eq!(allocs[0].allocated_capacity, 0.0);
    }

    #[test]
    fn test_many_flows_stress() {
        let flows: Vec<WmmfFlowRequest> = (0..100)
            .map(|i| WmmfFlowRequest {
                flow_id: format!("flow_{}", i),
                weight: 1.0,
                demand: 1000.0,
                min_guarantee: 0.0,
            })
            .collect();
        let allocs = WeightedMaxMinFairness::allocate(1000.0, &flows);
        // Equal weights, equal demand -> 10 each
        for a in &allocs {
            assert!((a.allocated_capacity - 10.0).abs() < 0.01);
        }
        let total: f64 = allocs.iter().map(|a| a.allocated_capacity).sum();
        assert!((total - 1000.0).abs() < 0.1);
    }

    #[test]
    fn test_trust_based_weight_scenario() {
        // Simulate ADG scenario: trusted host weight=1.0, suspicious host weight=0.5
        let flows = vec![
            WmmfFlowRequest { flow_id: "trusted".to_string(), weight: 1.0, demand: 80.0, min_guarantee: 10.0 },
            WmmfFlowRequest { flow_id: "suspicious".to_string(), weight: 0.5, demand: 80.0, min_guarantee: 0.0 },
        ];
        let allocs = WeightedMaxMinFairness::allocate(100.0, &flows);
        assert!(allocs[0].allocated_capacity > allocs[1].allocated_capacity,
            "Trusted flow must receive more than suspicious flow");
        let total: f64 = allocs.iter().map(|a| a.allocated_capacity).sum();
        assert!((total - 100.0).abs() < 0.01, "Must use full capacity");
    }
}
