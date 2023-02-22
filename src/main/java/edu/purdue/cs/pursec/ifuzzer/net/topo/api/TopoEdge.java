package edu.purdue.cs.pursec.ifuzzer.net.topo.api;

import com.google.gson.JsonObject;

import java.util.UUID;

public abstract class TopoEdge implements TopoElem {
    private UUID uuid;
    private State state;
    private String id;

    public TopoEdge() {
        this.uuid = UUID.randomUUID();
    }

    @Override
    public abstract TopoType type();

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public void setId(String id) {
        this.id = id;
    }

    @Override
    public State getState() {
        return this.state;
    }

    @Override
    public void setState(State state) {
        this.state = state;
    }

    @Override
    public UUID getUuid() {
        return this.uuid;
    }

    @Override
    public abstract String toString();

    @Override
    public JsonObject toJson() {
        return null;
    }

    public abstract String getSrcId();
    public abstract String getDstId();
    public abstract String getSrcPort();
    public abstract String getDstPort();
}
