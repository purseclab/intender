package edu.purdue.cs.pursec.ifuzzer.net.flow.impl;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.Box;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.Rule;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.VerifyRuleId;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.ResourceElem;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.*;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoEdge;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import jdd.bdd.BDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;

/* Code from pazz (Network) */
public class FlowRuleStore {
    private static Logger log = LoggerFactory.getLogger(FlowRuleStore.class);
    private BDD bdd;
    private final int headerLength;
    private Map<Long, Box> boxes = new LinkedHashMap<>();
    private Map<VerifyRuleId, Rule> flowRules = new LinkedHashMap<>();
    // Graph of a ruleId to a list of connected ruleIds
    private Map<VerifyRuleId, ArrayList<VerifyRuleId>> networkGraph = new HashMap<>();
    private Map<VerifyRuleId, ArrayList<VerifyRuleId>> inverseNetworkGraph = new LinkedHashMap<>();
    ArrayList<VerifyRuleId> inRuleList = new ArrayList<>();

    public FlowRuleStore(int headerLength) {
        this.headerLength = headerLength;
    }

    public void init() {
        this.bdd = new BDD(10000, 10000);
        for (int i = 0; i < headerLength; i++) {
            bdd.createVar();
        }
    }

    public void cleanUp() {
        if (bdd != null)
            bdd.cleanup();
        flowRules.clear();
        boxes.values().forEach(Box::cleanUp);
        boxes.clear();
        networkGraph.clear();
        inverseNetworkGraph.clear();
        inRuleList.clear();
    }

    public int getIntPredicate(String predicateStr) {
        return bdd.ref(bdd.minterm(predicateStr));
    }

    public BDD getBdd() {
        return bdd;
    }

    public Map<Long, Box> getBoxes() {
        return boxes;
    }

    public Map<VerifyRuleId, Rule> getFlowRules() {
        return flowRules;
    }

    public Map<VerifyRuleId, ArrayList<VerifyRuleId>> getNetworkGraph() {
        return networkGraph;
    }

    public Map<VerifyRuleId, ArrayList<VerifyRuleId>> getInverseNetworkGraph() {
        return inverseNetworkGraph;
    }

    public ArrayList<VerifyRuleId> getInRuleList(){
        return inRuleList;
    }

    public void generateInRuleList(IntentStore intentStore) {
        for (Intent baseIntent : intentStore.getAllAliveIntents()) {
            // TODO: H2H Intent
            if (!(baseIntent instanceof PointToPointIntent))
                continue;

            PointToPointIntent intent = (PointToPointIntent)baseIntent;

            for (ResourcePoint point : intent.getSrcList()) {
                Box box = boxes.get(ONOSUtil.getDpid(point.getDeviceId()));
                if (box != null) {
                    inRuleList.addAll(box.findInportToRuleMapping(Integer.parseInt(point.getPortNo())));
                }
            }
        }
    }

    public void storeFlowRules(List<Rule> flowRuleList) {
        // store global list
        flowRuleList.forEach(k -> flowRules.put(k.getrule_id(), k));

        // rule has dpid (Box), tableId (Box::tRules)
        Set<Box> todoBox = new HashSet<>();
        for (Rule flowRule : flowRuleList) {
            long boxId = flowRule.getDpid();
            Box box = boxes.computeIfAbsent(boxId, k -> new Box(bdd, boxId, flowRules));
            box.addRule(flowRule);
            todoBox.add(box);
        }

        // recalculate
        todoBox.forEach(Box::recalculatePredicates);
    }

    public void generateNetworkGraph(TopoGraph topoGraph) {
        // Iterate in all boxes in the network
        for (Box box : boxes.values()) {
            Map<Integer, LinkedList<VerifyRuleId>> tRules = box.getRules();
            // Inside each box iterate every table
            for (Integer tableId : tRules.keySet()) {
                LinkedList<VerifyRuleId> tableRules = tRules.get(tableId);
                // For each rule inside a table:
                for (VerifyRuleId ruleId : tableRules) {
                    ArrayList<VerifyRuleId> nextRules = new ArrayList<>();
                    Rule rule = flowRules.get(ruleId);
                    int portId = rule.getOutportId();
                    // If the rule drops a packet, the output port should be set to -1
                    if (rule.getOutportId() == -1)
                        continue;
                    // Find the next possible boxes by checking the topology for a physical link
                    TopoEdge edge = topoGraph.getEdgeFromSrc(ONOSUtil.getDpid(box.getBoxId()), String.valueOf(portId));
                    if (edge != null && edge.getDstPort() != null) {
                        // Retrieve the next physical port
                        int nextPhysicalPort = Integer.parseInt(edge.getDstPort());
                        // Find the next Box Identifier from the nextPort identifier
                        long nextBoxId = ONOSUtil.getDpid(edge.getDstId());
                        Box nextBox = boxes.get(nextBoxId);

                        if (nextBox != null) {
                            // Check the rules for the first table only "table 0"
                            LinkedList<VerifyRuleId> nextBoxRules = nextBox.getRules().get(0);
                            // Find the rule which its inport is connected to
                            // current rule, and its predicate overlaps with current rule
                            for (VerifyRuleId nextBoxRuleId : nextBoxRules) {
                                Rule nextRule = flowRules.get(nextBoxRuleId);
                                int portIndex = nextPhysicalPort % 10;
                                int nextRulePredicate = nextRule.getPredicates()[portIndex];
                                for (int localIndex = 1; localIndex < 7; localIndex++) {
                                    int rulePredicate = rule.getPredicates()[localIndex];
                                    if (rulePredicate != 0 && nextRulePredicate != 0 && bdd.and(rulePredicate, nextRulePredicate) != 0) {
                                        nextRules.add(nextRule.getrule_id());
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if (!nextRules.isEmpty()) {
                        networkGraph.put(rule.getrule_id(), nextRules);
                        for (VerifyRuleId nextRuleIds : nextRules) {
                            ArrayList<VerifyRuleId> connectedRuleIds = inverseNetworkGraph.computeIfAbsent(nextRuleIds, k -> new ArrayList<>());
                            if (!connectedRuleIds.contains(rule.getrule_id())) {
                                connectedRuleIds.add(rule.getrule_id());
                                inverseNetworkGraph.put(nextRuleIds, connectedRuleIds);
                            }
                        }
                    }
                }
            }

        }
        //cleanUp();
        System.out.println("The network graph is " + networkGraph.toString());
        System.out.println("The network graph is " + inverseNetworkGraph.toString());

    }

    /**
     * Singleton
     */
    private static class InnerFlowRuleStore {
        private static final FlowRuleStore instance = new FlowRuleStore(ConfigConstants.CONFIG_PAZZ_PACKET_HEADER_LEN);
    }

    public static FlowRuleStore getInstance() {
        return FlowRuleStore.InnerFlowRuleStore.instance;
    }
}
