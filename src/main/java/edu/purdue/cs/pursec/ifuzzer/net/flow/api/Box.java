package edu.purdue.cs.pursec.ifuzzer.net.flow.api;

import jdd.bdd.BDD;

import java.util.*;
import java.util.stream.Collectors;

// Box (i.e. Vagrant Box) has a bridge (device)
public class Box {
    private BDD bddObj;     // linked to FlowRuleStore
    private final long boxId;
    private Map<VerifyRuleId, Rule> flowRules;
    Map<Integer, LinkedList<VerifyRuleId>> tRules = new LinkedHashMap<>();
    Set<Integer> todoTables = new HashSet<>();

    public Box(BDD bdd, long boxId, Map<VerifyRuleId, Rule> flowRules) {
        this.bddObj = bdd;
        this.boxId = boxId;
        this.flowRules = flowRules;
    }

    public void cleanUp() {
        tRules.clear();
    }

    // In order to incorporate the dynamicity in the form of adding a new rule,
    // rule predicates must be recalculated
    public void addRule(Rule rule) {
        VerifyRuleId rule_id = rule.getrule_id();
        int predicate = rule.getPredicate();
        int table_id = rule.gettable_id();
        int priority = rule.getPriority();

        List<VerifyRuleId> table = tRules.computeIfAbsent(table_id, k -> new LinkedList<>());
        int pos = 0;
        for (pos = 0; pos < table.size(); pos++) {
            if (flowRules.get(table.get(pos)).priority <= priority) {
                table.add(pos, rule_id);
                break;
            }
        }
        if (pos == table.size())
            table.add(rule_id);

        todoTables.add(table_id);
    }

    private int diff(int a, int b) {
        int diff = bddObj.and(b, (bddObj.not(bddObj.and(b, a))));
        return diff;
    }

    /**
     * @return the bddObj
     */
    public BDD getBddObj() {
        return bddObj;
    }

    public void setBddObj(BDD bddObj) {
        this.bddObj = bddObj;
    }

    public void setFlowRules(Map<VerifyRuleId, Rule> flowRules) {
        this.flowRules = flowRules;
    }

    public List<VerifyRuleId> findRuleToPortMapping(int portId){
        return tRules.values()
                .stream()
                .flatMap(List::stream)
                .map(flowRules::get)
                .filter(k -> k.getOutportId() == portId)
                .map(Rule::getrule_id)
                .collect(Collectors.toList());
    }

    public List<VerifyRuleId> findInportToRuleMapping(int portId) {
        return tRules.get(0)
                .stream()
                .map(flowRules::get)
                .filter(k -> k.matchesInportId(portId))
                .map(Rule::getrule_id)
                .collect(Collectors.toList());
    }

    public Map<Integer, LinkedList<VerifyRuleId>> getRules() {
        return tRules;
    }

    public long getBoxId() {
        return boxId;
    }

    public void recalculatePredicates() {
        todoTables.forEach(this::recalculatePredicates);
        todoTables.clear();
    }

    // In a table, for each rule, subtract the domain from the domain of lower
    // priority rules
    public void recalculatePredicates(int table_id) {
        List<VerifyRuleId> rules = tRules.get(table_id);
        VerifyRuleId higherPriority_Rule_Id;
        VerifyRuleId lowerPriority_Rule_Id;
        int higherPriority_Rule_Predicate;
        int lowerPriority_Rule_Predicate;
        if (rules.size() < 1)
            return;

        /**
         *  TODO: We assume that box has 6 ports starting from 1-6, for each port
         *        subtract the predicate of lower priority rules from the higher
         *        priority rules
         **/
        for (int inPort_Index = 1; inPort_Index < 7; inPort_Index++) {
            for (int i = 1; i < rules.size(); i++) {
                // compare list.get(i) and list.get(j)
                lowerPriority_Rule_Id = rules.get(i);
                Rule rule = flowRules.get(lowerPriority_Rule_Id);
                lowerPriority_Rule_Predicate = rule.getPredicates()[inPort_Index];
                // If the lower priority predicate is 0, it means that it will
                // not match on that port
                if (lowerPriority_Rule_Predicate != 0) {
                    int lowerPriority_Rule_Predicate_OldValue = lowerPriority_Rule_Predicate;
                    for (int j = 0; j < i; j++) {
                        // Retrieve the rule object according to the rule_id and
                        // calculate difference of lower and higher priority
                        // rules
                        higherPriority_Rule_Id = rules.get(j);
                        higherPriority_Rule_Predicate = flowRules.get(higherPriority_Rule_Id)
                                .getPredicates()[inPort_Index];
                        // if the higher priority predicate is 0, then the rule
                        // will not match on that port
                        if (higherPriority_Rule_Predicate != 0)
                            lowerPriority_Rule_Predicate = diff(higherPriority_Rule_Predicate, lowerPriority_Rule_Predicate);

                    }
                    // Since we don't need the match predicate of the rule
                    // anymore, deref it from BDD to save memory
                    bddObj.deref(lowerPriority_Rule_Predicate_OldValue);
                    // Update the rule with the new predicate with respect to
                    // its priority
                    rule.setPredicateForPort(inPort_Index, bddObj.ref(lowerPriority_Rule_Predicate));
                    // Dot.setRemoveDotFile(false);
                    // Dot.setExecuteDot(false);
                    // bddObj.printDot("Difference",
                    // lowerPriorityRulePredicate);
                    //
                    //System.out.println("the predicate for " + lowerPriorityrule_id + " at port_index" + in_portIndex + " is " + lowerPriorityRulePredicate);
                }
            }
        }
    }

}
