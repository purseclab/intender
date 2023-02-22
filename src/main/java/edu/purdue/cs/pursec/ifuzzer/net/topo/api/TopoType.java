package edu.purdue.cs.pursec.ifuzzer.net.topo.api;

public class TopoType {
    private final String type;

    public static final TopoType DEVICE = new TopoType("device");
    public static final TopoType LINK = new TopoType("link");
    public static final TopoType HOST = new TopoType("host");
    public static final TopoType HOST_EDGE = new TopoType("host_edge");

    private TopoType(String type) {
        this.type = type;
    }

    public String toString() {
        return type;
    }

    public static TopoType getTypeFromEvent(String event) {
        TopoType type = new TopoType(event);
        return type;
    }
}
