package edu.purdue.cs.pursec.ifuzzer.fuzz.packet.api;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.net.flow.impl.FlowRuleStore;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.ReachabilityIntent;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;

import java.util.List;

public interface FuzzPacketGuidance {
    void init();
    void addTestIntent(TestIntent intent);
    void removeTestIntent(TestIntent intent);
    List<TestIntent> getTestIntents();
    JsonObject getValidTestJson(ReachabilityIntent intent);
    JsonObject getRandomPacketJson() throws EndFuzzException;
}
