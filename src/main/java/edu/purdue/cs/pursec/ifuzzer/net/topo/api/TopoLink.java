package edu.purdue.cs.pursec.ifuzzer.net.topo.api;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;

public class TopoLink extends TopoEdge {
    private final TopoType type = TopoType.LINK;
    private String linkType;
    private String srcId;
    private String dstId;
    private String srcPort;
    private String dstPort;

    public TopoLink(JsonObject jObject) {
        super();
        if (jObject.get("src") != null) {
            if (jObject.get("src").isJsonObject()) {
                JsonObject jSrc = jObject.get("src").getAsJsonObject();
                if (jSrc.get("device") != null) {
                    srcId = jSrc.get("device").getAsString();
                }
                if (jSrc.get("port") != null) {
                    srcPort = jSrc.get("port").getAsString();
                }
            } else {
                // deprecated
                srcId = jObject.get("src").getAsString();
            }
        }

        if (jObject.get("dst") != null) {
            if (jObject.get("dst").isJsonObject()) {
                JsonObject jDst = jObject.get("dst").getAsJsonObject();
                if (jDst.get("device") != null) {
                    dstId = jDst.get("device").getAsString();
                }
                if (jDst.get("port") != null) {
                    dstPort = jDst.get("port").getAsString();
                }
            } else {
                dstId = jObject.get("dst").getAsString();
            }
        }

        super.setId(ONOSUtil.getLinkId(srcId, dstId, srcPort, dstPort));

        if (jObject.get("link_type") != null)
            linkType = jObject.get("link_type").getAsString();
        else if (jObject.get("type") != null)
            linkType = jObject.get("type").getAsString();

        if (jObject.get("state") != null)
            super.setState(State.of(jObject.get("state").getAsString().toUpperCase()));
        else
            super.setState(State.ACTIVE);
    }

    public TopoLink(String srcId, String dstId, String srcPort, String dstPort) {
        super();
        this.srcId = srcId;
        this.dstId = dstId;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        super.setId(ONOSUtil.getLinkId(srcId, dstId, srcPort, dstPort));
    }

    public static TopoLink invert(TopoLink topoLink) {
        return new TopoLink(topoLink.dstId, topoLink.srcId, topoLink.dstPort, topoLink.srcPort);
    }

    @Override
    public TopoType type() {
        return this.type;
    }

    @Override
    public String toString() {
        JsonObject linkJson = this.toJson();

        if (this.getState() != null)
            linkJson.addProperty("state", this.getState().toString());

        return linkJson.toString();
    }

    @Override
    public String getSrcId() { return this.srcId; }

    @Override
    public String getDstId() { return this.dstId; }

    @Override
    public String getSrcPort() {
        return this.srcPort;
    }

    public void setSrcPort(String srcPort) {
        this.srcPort = srcPort;
    }

    @Override
    public String getDstPort() {
        return this.dstPort;
    }

    public void setDstPort(String dstPort) {
        this.dstPort = dstPort;
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
