package edu.purdue.cs.pursec.ifuzzer.fuzz.packet.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion.Type;
import edu.purdue.cs.pursec.ifuzzer.criterion.impl.IPCriterion;
import edu.purdue.cs.pursec.ifuzzer.fuzz.packet.api.FuzzPacketGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.packet.api.TestIntent;
import edu.purdue.cs.pursec.ifuzzer.net.flow.impl.FlowRuleStore;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.PointToPointIntent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.ReachabilityIntent;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;

import java.util.*;

public class NoPacketGuidance implements FuzzPacketGuidance {
    private final Random rand = new Random();
    private static final TopoGraph topoGraph = TopoGraph.getOperationalTopology();
    private static final FlowRuleStore flowRuleStore = FlowRuleStore.getInstance();
    private TestIntent testIntent;

    @Override
    public void init() {}

    @Override
    public void addTestIntent(TestIntent intent) {
        testIntent = intent;
    }

    @Override
    public void removeTestIntent(TestIntent intent) {
        if (testIntent == intent)
            testIntent = null;
    }

    @Override
    public JsonObject getValidTestJson(ReachabilityIntent intent) {
        JsonObject testJson;
        if (intent instanceof PointToPointIntent) {
            PointToPointIntent p2pIntent = (PointToPointIntent)intent;
            String srcIP = "10.0.0.1";
            String dstIP = "10.0.0.2";

            for (Criterion criterion : p2pIntent.getCriteriaList()) {
                if (criterion.type().equals(Type.IPV4_SRC)) {
                    IPCriterion ipCriterion = (IPCriterion) criterion;
                    srcIP = FuzzUtil.randomIp(ipCriterion.ip(), rand);
                }

                if (criterion.type().equals(Type.IPV4_DST)) {
                    IPCriterion ipCriterion = (IPCriterion) criterion;
                    dstIP = FuzzUtil.randomIp(ipCriterion.ip(), rand);
                }
            }

            testJson = p2pIntent.toTestJson(topoGraph);
            if (testJson != null) {
                testJson.addProperty("src", srcIP);
                testJson.addProperty("dst", dstIP);
            }
        } else {
            testJson = intent.toTestJson(topoGraph);
        }

        return testJson;
    }

    @Override
    public JsonObject getRandomPacketJson() {
        if (testIntent == null)
            return null;

        return getValidTestJson(testIntent.getIntent());
    }

    @Override
    public List<TestIntent> getTestIntents() {
        return Collections.singletonList(testIntent);
    }
}
