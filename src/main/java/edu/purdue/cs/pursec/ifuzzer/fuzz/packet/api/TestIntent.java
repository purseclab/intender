package edu.purdue.cs.pursec.ifuzzer.fuzz.packet.api;

import edu.purdue.cs.pursec.ifuzzer.net.intent.api.ResourceElem;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.ReachabilityIntent;

public class TestIntent {
    ReachabilityIntent intent;
    String key;
    int seq;
    String actionId;

    public TestIntent(ReachabilityIntent intent, String key, int seq, String actionId) {
        this.intent = intent;
        this.key = key;
        this.seq = seq;
        this.actionId = actionId;
    }

    public ReachabilityIntent getIntent() {
        return intent;
    }

    public String getKey() {
        return key;
    }

    public int getSeq() {
        return seq;
    }

    public String getActionId() {
        return actionId;
    }
}
