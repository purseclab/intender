package edu.purdue.cs.pursec.ifuzzer.net.topo.api;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;

public class TopoHostEdge extends TopoEdge {
    private final TopoType type = TopoType.HOST_EDGE;
    private String srcId;
    private String dstId;
    private String srcPort;
    private String dstPort;

    public TopoHostEdge(String srcId, String dstId, String srcPort, String dstPort) {
        super.setState(State.ACTIVE);
        this.srcId = srcId;
        this.dstId = dstId;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        super.setId(ONOSUtil.getLinkId(srcId, dstId, srcPort, dstPort));
    }

    @Override
    public TopoType type() {
        return this.type;
    }

    @Override
    public String toString() {
        JsonObject json = this.toJson();

        if (this.getState() != null)
            json.addProperty("state", this.getState().toString());

        return json.toString();
    }

    @Override
    public String getSrcId() {
        return this.srcId;
    }

    @Override
    public String getDstId() {
        return this.dstId;
    }

    @Override
    public String getSrcPort() {
        return this.srcPort;
    }

    @Override
    public String getDstPort() {
        return this.dstPort;
    }

    @Override
    public JsonObject toJson() {
        JsonObject jObject = new JsonObject();

        JsonObject srcJson = new JsonObject();
        srcJson.addProperty("device", srcId);
        srcJson.addProperty("port", srcPort);
        jObject.add("src", srcJson);

        JsonObject dstJson = new JsonObject();
        dstJson.addProperty("device", dstId);
        dstJson.addProperty("port", dstPort);
        jObject.add("dst", dstJson);

        return jObject;
    }
}
