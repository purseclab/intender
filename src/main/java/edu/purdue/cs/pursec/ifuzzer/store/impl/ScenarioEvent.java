package edu.purdue.cs.pursec.ifuzzer.store.impl;

import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.store.api.StoreEvent;

public class ScenarioEvent implements StoreEvent {
    String eventType;   // APPLY, SYNC, FINISH, ERROR
    String key;
    FuzzAction action;
    String result;
    Object content = null;
    int seq;

    public ScenarioEvent(String eventType) {
        this.eventType = eventType;
        this.key = null;
        this.action = null;
    }

    public ScenarioEvent(String eventType, String key, int seq, FuzzAction action) {
        this.eventType = eventType;
        this.key = key;
        this.action = action;
        this.seq = seq;
    }

    public ScenarioEvent(String eventType, Object content) {
        this.eventType = eventType;
        this.content = content;
    }

    public String getKey() {
        return key;
    }

    public int getSeq() {
        return seq;
    }

    public FuzzAction getAction() {
        return action;
    }

    public String getEventType() {
        return eventType;
    }

    public Object getContent() {
        return content;
    }
}
