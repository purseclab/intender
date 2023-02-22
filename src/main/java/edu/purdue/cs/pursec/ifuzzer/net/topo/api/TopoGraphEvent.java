package edu.purdue.cs.pursec.ifuzzer.net.topo.api;

public class TopoGraphEvent {
    public enum Type {
        PUT,
        REMOVE
    }

    private final TopoElem elem;
    private final Type type;

    public TopoGraphEvent(TopoElem elem, Type type) {
        this.elem = elem;
        this.type = type;
    }

    public TopoElem getElem() {
        return elem;
    }

    public Type getType() {
        return type;
    }
}
