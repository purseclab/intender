package edu.purdue.cs.pursec.ifuzzer.net.topo.api;

import com.google.gson.JsonObject;

import java.util.UUID;

public abstract class TopoNode implements TopoElem {
    private UUID uuid;
    private State state;
    private String id;

    public TopoNode() {
        this.uuid = UUID.randomUUID();
        this.id = uuid.toString();
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

    public boolean compare(TopoNode node) {
        // Don't compare UUID

        if (!this.id.equals(node.getId()))
            return false;

        return true;
    }

    public abstract String getAddr();
}
