package edu.purdue.cs.pursec.ifuzzer.net.topo.api;

import com.google.gson.JsonObject;

import java.util.UUID;

public interface TopoElem {
    enum State {
        ACTIVE ("ACTIVE"),
        INACTIVE ("INACTIVE");

        private final String state;

        private State(String state) {
            this.state = state;
        }

        public boolean equals(String state) {
            return this.state.equals(state);
        }
        public boolean equals(State state) {
            return this.equals(state.toString());
        }

        public String toString() {
            return this.state;
        }

        public State reverse() {
            if (this.state.equals(ACTIVE.state))
                return INACTIVE;
            else if (this.state.equals(INACTIVE.state))
                return ACTIVE;
            return null;
        }

        public static State of (boolean isActive) {
            return (isActive ? ACTIVE : INACTIVE);
        }

        public static State of (String state) {
            if (state.equals(ACTIVE.state))
                return ACTIVE;
            else if (state.equals(INACTIVE.state))
                return INACTIVE;
            return null;
        }
    }

    TopoType type();
    String getId();
    void setId(String id);
    State getState();
    void setState(State state);
    UUID getUuid();
    String toString();
    JsonObject toJson();
}
