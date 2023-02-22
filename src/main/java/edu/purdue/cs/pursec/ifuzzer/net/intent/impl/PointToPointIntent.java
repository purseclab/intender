package edu.purdue.cs.pursec.ifuzzer.net.intent.impl;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.api.ONOSConstants;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentType;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.ONOSIntent;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;

import java.io.IOException;

public class PointToPointIntent extends ReachabilityIntent<ResourcePoint> implements ONOSIntent {
    private static final IntentType type = IntentType.PointToPointIntent;
    private final String restRoute = "/send";
    private String appId = ONOSConstants.ONOS_APP_ID;

    public PointToPointIntent(ResourcePoint src, ResourcePoint dst) {
        super(ONOSConstants.ONOS_INTENT_DEFAULT_PRIORITY);
        super.setState(State.REQ);
        super.setSrc(src);
        super.setDst(dst);
    }

    public PointToPointIntent(JsonObject jObject) throws IOException {
        super(jObject);
        // TODO: support 1.9
        if (jObject.has("ingressPoint")) {
            JsonObject ingressPoint = jObject.get("ingressPoint").getAsJsonObject();
            if (ingressPoint.get("device") != null &&
                    ingressPoint.get("port") != null) {
                this.setSrc(new ResourcePoint(ingressPoint.get("device").getAsString(),
                        ingressPoint.get("port").getAsString()));
            }
        }

        if (jObject.has("egressPoint")) {
            JsonObject egressPoint = jObject.get("egressPoint").getAsJsonObject();
            if (egressPoint.get("device") != null &&
                    egressPoint.get("port") != null) {
                this.setDst(new ResourcePoint(egressPoint.get("device").getAsString(),
                        egressPoint.get("port").getAsString()));
            }
        }

        if (jObject.has("priority"))
            this.setPriority(jObject.get("priority").getAsInt());

    }

    public static PointToPointIntent of(JsonObject jObject) throws IOException {
        if (jObject != null &&
                jObject.has("type") &&
                jObject.get("type").getAsString().equals(type.toString()))
            return new PointToPointIntent(jObject);

        return null;
    }

    @Override
    public JsonObject toJson(String onosVersion) {
        JsonObject jObject = new JsonObject();
        jObject.addProperty("key", super.getKey());
        jObject.addProperty("type", type.toString());
        jObject.addProperty("appId", appId);
        jObject.addProperty("priority", super.getPriority());

        JsonObject jIngress = new JsonObject();
        jIngress.addProperty("device", getSrc().getDeviceId());
        jIngress.addProperty("port", getSrc().getPortNo());
        jObject.add("ingressPoint", jIngress);

        JsonObject jEgress = new JsonObject();
        jEgress.addProperty("device", getDst().getDeviceId());
        jEgress.addProperty("port", getDst().getPortNo());
        jObject.add("egressPoint", jEgress);

        return jObject;
    }
    @Override
    public String getAppId() {
        return this.appId;
    }

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }

    @Override
    public JsonObject toTestJson(TopoGraph topoGraph) {
        if (getSrc() == null || getDst() == null)
            return null;

        JsonObject jObject = super.toTestJson(topoGraph);

        // SRC/DST -> packet addr, SENDER/RECEIVER -> position (host addr or dp/port)
        jObject.addProperty("src", "10.0.0.1");     // TODO: randomize src
        jObject.addProperty("dst", "10.0.0.2");     // TODO: randomize dst

        JsonArray sendersJson = new JsonArray();
        sendersJson.add(getSrc().getDeviceId() + "/" + getSrc().getPortNo());
        jObject.add("senders", sendersJson);

        JsonArray receiversJson = new JsonArray();
        receiversJson.add(getDst().getDeviceId() + "/" + getDst().getPortNo());
        jObject.add("receivers", receiversJson);

        return jObject;
    }

    public JsonObject toTestJson(TopoGraph topoGraph, String seq) {
        JsonObject jObject = toTestJson(topoGraph);
        if (jObject != null)
            jObject.addProperty("seq", seq);

        return jObject;
    }

    @Override
    public String getRESTRoute() {
        return this.restRoute;
    }

    @Override
    public boolean equalsConfig(Intent intent) {
        if (!super.equalsConfig(intent))
            return false;

        if (!(intent instanceof PointToPointIntent))
            return false;

        PointToPointIntent p2pIntent = (PointToPointIntent)intent;

        if (!this.appId.equals(p2pIntent.appId))
            return false;

        if (this.getSrc() != null && p2pIntent.getSrc() != null) {
            if (!this.getSrc().getDeviceId().equals(p2pIntent.getSrc().getDeviceId()))
                return false;

            if (!this.getSrc().getPortNo().equals(p2pIntent.getSrc().getPortNo()))
                return false;

        } else if (!(this.getSrc() == null && p2pIntent.getSrc() == null)) {
            return false;
        }

        if (this.getDst() != null && p2pIntent.getDst() != null) {
            if (!this.getDst().getDeviceId().equals(p2pIntent.getDst().getDeviceId()))
                return false;

            if (!this.getDst().getPortNo().equals(p2pIntent.getDst().getPortNo()))
                return false;

        } else if (!(this.getDst() == null && p2pIntent.getDst() == null)) {
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

        if (this.getSrc().getDeviceId().equals(this.getDst().getDeviceId()) &&
                this.getSrc().getPortNo().equals(this.getDst().getPortNo()))
            return true;

        return false;
    }
}
