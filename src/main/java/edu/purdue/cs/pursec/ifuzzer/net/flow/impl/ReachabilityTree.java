package edu.purdue.cs.pursec.ifuzzer.net.flow.impl;

import edu.purdue.cs.pursec.ifuzzer.net.flow.api.Box;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.Rule;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.VerifyPortId;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.VerifyRuleId;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.ResourcePoint;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import jdd.bdd.BDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/* Code from pazz */
public class ReachabilityTree {
    private static Logger log = LoggerFactory.getLogger(ReachabilityTree.class);
    BDD bdd;
    Map<Long, Box> boxes;
    Stack<VerifyRuleId> currentPathInt = new Stack<>();
    Stack<Integer> currentPredicates = new Stack<>();
    Stack<VerifyPortId> currentPorts = new Stack<>();

    Map<VerifyRuleId, ArrayList<VerifyRuleId>> inverseNetworkGraph;
    Map<VerifyRuleId, ArrayList<VerifyRuleId>> networkGraph;
    Map<VerifyRuleId, Rule> networkRules;
    ArrayList<VerifyRuleId> inRuleList;

    ArrayList<VerifyRuleId> onList = new ArrayList<>();
    ArrayList<ArrayList<Integer>> pathPredicates = new ArrayList<ArrayList<Integer>>();
    ArrayList<ArrayList<VerifyRuleId>> paths = new ArrayList<>();
    ArrayList<ArrayList<VerifyPortId>> ports = new ArrayList<>();
    ArrayList<Integer> predicates = new ArrayList<Integer>();
    Rule outRule;

    PathWrapper wrapper = null;
    private static final int wrapperCacheMaxLen = 1024;
    Map<String, PathWrapper> wrapperCache = new LinkedHashMap<>();
    int headerLength;

    public ReachabilityTree(Map<VerifyRuleId, ArrayList<VerifyRuleId>> networkGraph,
                            Map<VerifyRuleId, ArrayList<VerifyRuleId>> inverseNetworkGraph, Map<VerifyRuleId, Rule> networkRules,
                            ArrayList<VerifyRuleId> inRuleList, Map<Long, Box> boxes, int headerLength) {
        this.networkGraph = networkGraph;
        //log.debug("network graph s"+networkGraph.toString());
        this.inverseNetworkGraph = inverseNetworkGraph;
        //log.debug("Inverse network graph is" + inverseNetworkGraph.toString());

        this.networkRules = networkRules;
        this.inRuleList = inRuleList;
        this.boxes = boxes;
        this.headerLength = headerLength;
        bdd = new BDD(10000, 10000);
        for (int i = 0; i < headerLength; i++) {
            bdd.ref(bdd.createVar());
        }
        initRules();
    }

    public BDD getBDD(){
        return this.bdd;
    }

    private void addWrapperCache(String wrapperCacheId, PathWrapper wrapper) {
        if (wrapperCache.size() >= wrapperCacheMaxLen) {
            wrapperCache.remove(wrapperCache.keySet().iterator().next());
        }
        wrapperCache.put(wrapperCacheId, wrapper);
    }

    public PathWrapper findReversePath(String dpid, int egressPort, String packetHeader) {
        //log.debug("Request is in reachability tree" + egressPort + " packet header " + packetHeader
        //        + "packet header length is " + packetHeader.length());
        int predicate = bdd.ref(bdd.minterm(packetHeader));
        String wrapperCacheId = String.format("%s/%d/%d", dpid, egressPort, predicate);
        if (wrapperCache.containsKey(wrapperCacheId)) {
            return wrapperCache.get(wrapperCacheId);
        }

        //log.debug("the predicate is" + predicate);
        generateInverseReachabilityFromPort(dpid, egressPort, predicate);
        PathWrapper retWrapper = getPathsAndPorts();
        addWrapperCache(wrapperCacheId, retWrapper);
        log.debug("Sending the result, the result is " + retWrapper.pathAndPortStrings().toString());
        return retWrapper;
    }

    public int getHeaderSpace(ResourcePoint inPoint, ResourcePoint outPoint){
        Box inBox = boxes.get(ONOSUtil.getDpid(inPoint.getDeviceId()));
        Box outBox = boxes.get(ONOSUtil.getDpid(outPoint.getDeviceId()));
        reInitialize();
        for(VerifyRuleId inRuleId: inBox.findInportToRuleMapping(Integer.parseInt(inPoint.getPortNo()))) {
            for(VerifyRuleId outRuleId: outBox.findRuleToPortMapping(Integer.parseInt(outPoint.getPortNo()))) {
                this.outRule = networkRules.get(outRuleId);
                generateReachability(networkRules.get(inRuleId), bdd.getOne());
            }
        }
        int union = bdd.getZero();
        for(int pred: predicates){
            union = bdd.orTo(pred, union);
        }
        return bdd.ref(union);
    }

    private void generateReachability(Rule inRule, int predicate) {
        int newPredicate = 0;
        int[] inRulePredicates = inRule.getPredicates();
        for (int inPort = 1; inPort < 7; inPort++) {
            int pred = inRulePredicates[inPort];
//            log.debug("Inverse Reachability, rule predicate is "+ pred
//                    + " rule is "+ inRule.getrule_id());
            if (pred != 0) {
                newPredicate = bdd.andTo(pred, predicate);
//                log.debug("new predicate is "+ newPredicate);
                if (newPredicate != 0) {
                    currentPathInt.push(inRule.getrule_id());
                    currentPorts.push(new VerifyPortId(inRule.getDpid(), inPort));
                    currentPredicates.push(newPredicate);
                    if (!onList.contains(inRule.getrule_id()))
                        onList.add(inRule.getrule_id());
                    // Check the set of possible input rules
                    if (inRule.getrule_id() == outRule.getrule_id()) {
                        bdd.ref(newPredicate);
                        predicates.add(newPredicate);
                    } else {
                        ArrayList<VerifyRuleId> rules = networkGraph.get(inRule.getrule_id());
                        if (rules != null)
                            for (VerifyRuleId rule : rules) {
                                if (!onList.contains(rule)) {
                                    generateReachability(networkRules.get(rule), newPredicate);
                                }
                            }
                    }
                }
            }
        }
        if (!currentPathInt.isEmpty())
            currentPathInt.pop();

        onList.remove(inRule.getrule_id());

        if (!currentPorts.isEmpty())
            currentPorts.pop();
        // if (!currentPredicates.isEmpty())
        // currentPredicates.pop();

    }

    private void generateInverseReachability(Rule inRule, int predicate) {
        int newPredicate;
        int[] inRulePredicates = inRule.getPredicates();
        for (int inPort = 1; inPort < 7; inPort++) {
            int pred = inRulePredicates[inPort];
//            log.debug("Inverse Reachability, rule predicate is"+pred
//                    + "rule is is "+ inRule.getrule_id());
            if (pred != 0) {
                newPredicate = bdd.andTo(pred, predicate);
                //log.debug("new predicate is" + newPredicate);
                if (newPredicate != 0) {
                    currentPathInt.push(inRule.getrule_id());
                    currentPorts.push(new VerifyPortId(inRule.getDpid(), inPort));
                    // currentPredicates.push(newPredicate);
                    if (!onList.contains(inRule.getrule_id()))
                        onList.add(inRule.getrule_id());
                    // Check the set of possible input rules
                    if (inRuleList.contains(inRule.getrule_id())) {
                        paths.add(new ArrayList<>(currentPathInt));
                        ports.add(new ArrayList<>(currentPorts));
                        // pathPredicates.add(new
                        // ArrayList<Integer>(currentPredicates));
                        // for (int pr : currentPredicates) {
                        // bdd.ref(pr);
                        // }
                    } else {
                        // log.debug("Getting previous rules");
                        // log.debug("Previous rules are"+
                        // inverseNetworkGraph.toString());

                        ArrayList<VerifyRuleId> rules = inverseNetworkGraph.get(inRule.getrule_id());
                        if (rules != null)
                            for (VerifyRuleId rule : rules) {
                                if (!onList.contains(rule)) {
                                    generateInverseReachability(networkRules.get(rule), newPredicate);
                                }
                            }
                    }
                }
            }
        }
        if (!currentPathInt.isEmpty())
            currentPathInt.pop();
        onList.remove(inRule.getrule_id());
        if (!currentPorts.isEmpty())
            currentPorts.pop();
        // if (!currentPredicates.isEmpty())
        // currentPredicates.pop();

    }

    public void setOutRule(Rule rule) {
        this.outRule = rule;
    }

    private void generateInverseReachabilityFromPort(String dpid, int portId, int predicate) {
        Box box = boxes.get(ONOSUtil.getDpid(dpid));
        wrapper = new PathWrapper();
        for (VerifyRuleId ruleId : box.findRuleToPortMapping(portId)) {
            //log.debug("RuleID is " + ruleId);
            generateInverseReachability(networkRules.get(ruleId), predicate);
            if (!paths.isEmpty()) {
                //log.debug("adding paths");
                wrapper.addPaths(paths);
                wrapper.addPorts(ports);
                // wrapper.addPredicates(pathPredicates);

            }
            reInitialize();
            //log.debug("reinitializing " + wrapper.pathStrings().toString());

        }
        //log.debug("Path found " + wrapper.pathStrings().toString());

    }

    private PathWrapper getPathsAndPorts() {
        //log.debug("Get path and predicate");

        PathWrapper deepCopiedWrapper = new PathWrapper(wrapper);
        //log.debug("Get Paths and predicates: " + wrapper.pathStrings().toString());
        //log.debug("portList is" + wrapper.portStrings().toString());
        wrapper = null;
        return deepCopiedWrapper;
    }

    private void initRules() {
        for (Box box : boxes.values()) {
            for (int tableId : box.getRules().keySet()) {
                List<VerifyRuleId> rules = box.getRules().get(tableId);
                for (VerifyRuleId ruleId : rules) {
                    networkRules.get(ruleId).reCalculatePredicate(bdd);
                }
                box.setBddObj(bdd);
                box.setFlowRules(networkRules);
                box.recalculatePredicates(tableId);
            }
        }
    }

    /**
     * @return the networkGraph
     */
    public Map<VerifyRuleId, ArrayList<VerifyRuleId>> getNetworkGraph() {
        return networkGraph;
    }
    /**
     * @param networkGraph the networkGraph to set
     */
    public void setNetworkGraph(Map<VerifyRuleId, ArrayList<VerifyRuleId>> networkGraph) {
        this.networkGraph = networkGraph;
    }
    /**
     * @return the networkRules
     */
    public Map<VerifyRuleId, Rule> getNetworkRules() {
        return networkRules;
    }
    /**
     * @param networkRules the networkRules to set
     */
    public void setNetworkRules(Map<VerifyRuleId, Rule> networkRules) {
        this.networkRules = networkRules;
    }
    private void reInitialize() {
        currentPathInt.clear();
        currentPorts.clear();
        predicates.clear();
        this.outRule = null;
        // currentPredicates.clear();
        paths.clear();
        ports.clear();
        onList.clear();
        // pathPredicates.clear();
    }
}
