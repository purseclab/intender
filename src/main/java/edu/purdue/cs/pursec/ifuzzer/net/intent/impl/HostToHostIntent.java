package edu.purdue.cs.pursec.ifuzzer.net.intent.impl;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.api.ONOSConstants;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentType;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.ONOSIntent;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoNode;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;

import java.io.IOException;

public class HostToHostIntent extends ReachabilityIntent<ResourceHost> implements ONOSIntent {
    private static final IntentType type = IntentType.HostToHostIntent;
    private final String restRoute = "/ping";
    private String appId = ONOSConstants.ONOS_APP_ID;

    public HostToHostIntent(ResourceHost src, ResourceHost dst) {
        super(ONOSConstants.ONOS_INTENT_DEFAULT_PRIORITY);
        super.setState(State.REQ);
        super.setSrc(src);
        super.setDst(dst);
    }

    public HostToHostIntent(JsonObject jObject) throws IOException {
        super(jObject);
        if (jObject.get("one") != null)
            this.setSrc(new ResourceHost(jObject.get("one").getAsString()));
        if (jObject.get("two") != null)
            this.setDst(new ResourceHost(jObject.get("two").getAsString()));
    }

    public static HostToHostIntent of(JsonObject jObject) throws IOException {
        if (jObject != null &&
                jObject.get("type") != null &&
                jObject.get("type").getAsString().equals(type.toString()))
            return new HostToHostIntent(jObject);

        return null;
    }

    @Override
    public JsonObject toJson(String onosVersion) {
        if (getSrc() == null || getDst() == null)
            return null;

        JsonObject jObject = new JsonObject();
        jObject.addProperty("key", super.getKey());
        jObject.addProperty("type", type.toString());
        jObject.addProperty("appId", appId);
        jObject.addProperty("priority", super.getPriority());
        jObject.addProperty("one", getSrc().getHostId());
        jObject.addProperty("two", getDst().getHostId());

        return jObject;
    }

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }

    @Override
    public String getAppId() {
        return this.appId;
    }

    @Override
    public JsonObject toTestJson(TopoGraph topoGraph) {
        JsonObject jsonObject = super.toTestJson(topoGraph);

        if (getSrc() == null || getDst() == null)
            return null;

        TopoNode topoSrc = topoGraph.getNode(getSrc().getHostId());
        TopoNode topoDst = topoGraph.getNode(getDst().getHostId());

        if (topoSrc == null || topoDst == null)
            return null;

        jsonObject.addProperty("src", topoSrc.getAddr());
        jsonObject.addProperty("dst", topoDst.getAddr());

        return jsonObject;
    }

    @Override
    public String getRESTRoute() {
        return this.restRoute;
    }

    @Override
    public boolean equalsConfig(Intent intent) {
        if (!super.equalsConfig(intent))
            return false;

        if (!(intent instanceof HostToHostIntent))
            return false;

        HostToHostIntent h2hIntent = (HostToHostIntent)intent;

        if (!this.appId.equals(h2hIntent.appId))
            return false;

        if (this.getSrc() != null && h2hIntent.getSrc() != null) {
            if (!this.getSrc().getHostId().toLowerCase().equals(h2hIntent.getSrc().getHostId().toLowerCase()))
                return false;

        } else if (!(this.getSrc() == null && h2hIntent.getSrc() == null)) {
            return false;
        }

        if (this.getDst() != null && h2hIntent.getDst() != null) {
            if (!this.getDst().getHostId().toLowerCase().equals(h2hIntent.getDst().getHostId().toLowerCase()))
                return false;

        } else if (!(this.getDst() == null && h2hIntent.getDst() == null)) {
            return false;
        }

        return true;
    }

    @Override
    public boolean isValid() {
        if (getSrc() == null || getDst() == null)
            return false;
        return (getSrc().isValid() && getDst().isValid());
    }

    @Override
    public boolean doNotDPTest() {
        if (this.getSrc() == null || this.getDst() == null)
            return false;

        if (this.getSrc().getHostId().equals(this.getDst().getHostId()))
            return true;

        return false;
    }
}
