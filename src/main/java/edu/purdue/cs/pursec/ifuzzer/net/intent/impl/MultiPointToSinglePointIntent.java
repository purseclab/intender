package edu.purdue.cs.pursec.ifuzzer.net.intent.impl;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.api.ONOSConstants;
import edu.purdue.cs.pursec.ifuzzer.api.TestConstants;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentType;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.ONOSIntent;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;

import java.io.IOException;

public class MultiPointToSinglePointIntent extends ReachabilityIntent<ResourcePoint> implements ONOSIntent {
    private static final IntentType type = IntentType.MultiPointToSinglePointIntent;
    private final String restRoute = "/send";
    private String appId = ONOSConstants.ONOS_APP_ID;

    public MultiPointToSinglePointIntent() {
        super(ONOSConstants.ONOS_INTENT_DEFAULT_PRIORITY);
    }

    public MultiPointToSinglePointIntent(JsonObject jObject) throws IOException {
        super(jObject);

        // TODO: support 1.9
        if (jObject.get("ingressPoint") != null) {
            JsonArray ingressPoints = jObject.get("ingressPoint").getAsJsonArray();
            for (JsonElement ingressPointElem : ingressPoints) {
                JsonObject ingressPoint = ingressPointElem.getAsJsonObject();
                if (ingressPoint.get("device") != null &&
                        ingressPoint.get("port") != null) {
                    this.addSrc(new ResourcePoint(ingressPoint.get("device").getAsString(),
                            ingressPoint.get("port").getAsString()));
                }
            }
        }

        if (jObject.get("egressPoint") != null) {
            JsonObject egressPoint = jObject.get("egressPoint").getAsJsonObject();
            if (egressPoint.get("device") != null &&
                    egressPoint.get("port") != null) {
                this.setDst(new ResourcePoint(egressPoint.get("device").getAsString(),
                        egressPoint.get("port").getAsString()));
            }
        }

        if (jObject.get("priority") != null)
            this.setPriority(jObject.get("priority").getAsInt());
    }

    public static MultiPointToSinglePointIntent of(JsonObject jObject) throws IOException {
        if (jObject != null &&
                jObject.get("type") != null &&
                jObject.get("type").getAsString().equals(type.toString()))
            return new MultiPointToSinglePointIntent(jObject);

        return null;
    }

    /* Example
        {
          "type": "SinglePointToMultiPointIntent",
          "appId": "org.onosproject.null",
          "priority": 55,
          "egressPoint": [
            {
              "port": "2",
              "device": "of:0000000000000002"
            },
            {
              "port": "2",
              "device": "of:0000000000000003"
            }
          ],
          "ingressPoint": {
            "port": "1",
            "device": "of:0000000000000001"
          }
        }
     */

    @Override
    public JsonObject toJson(String onosVersion) {
        JsonObject jObject = new JsonObject();
        jObject.addProperty("key", getKey());
        jObject.addProperty("type", type.toString());
        jObject.addProperty("appId", appId);
        jObject.addProperty("priority", getPriority());

        JsonArray jIngressArr = new JsonArray();
        for (ResourcePoint src : getSrcList()) {
            JsonObject jIngress = new JsonObject();
            jIngress.addProperty("device", src.getDeviceId());
            jIngress.addProperty("port", src.getPortNo());
            jIngressArr.add(jIngress);
        }
        if (onosVersion.equals("1.9.0")) {
            JsonObject jIngresses = new JsonObject();
            jIngresses.add("connectPoints", jIngressArr);
            jObject.add("ingressPoint", jIngresses);
        } else {
            jObject.add("ingressPoint", jIngressArr);
        }

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
        JsonObject jObject = new JsonObject();
        jObject.addProperty("key", getKey());
        jObject.addProperty("ret_url", TestConstants.TEST_MANAGER_URL + TestConstants.TEST_RET_ROUTE);

        // SRC/DST -> packet addr, SENDER/RECEIVER -> position (host addr or dp/port)
        jObject.addProperty("src", "10.0.0.1");     // TODO: randomize src
        jObject.addProperty("dst", "10.0.0.2");     // TODO: randomize dst

        JsonArray sendersJson = new JsonArray();
        for (ResourcePoint src : getSrcList()) {
            sendersJson.add(src.getDeviceId() + "/" + src.getPortNo());
        }
        jObject.add("senders", sendersJson);

        JsonArray receiversJson = new JsonArray();
        receiversJson.add(getDst().getDeviceId() + "/" + getDst().getPortNo());
        jObject.add("receivers", receiversJson);

        return jObject;
    }

    public JsonObject toTestJson(TopoGraph topoGraph, String seq) {
        JsonObject jObject = toTestJson(topoGraph);
        jObject.addProperty("seq", seq);

        return jObject;
    }
    @Override
    public String getRESTRoute() {
        return this.restRoute;
    }

    @Override
    public boolean isValid() {
        // TODO
        return true;
    }

    @Override
    public boolean doNotDPTest() {
        return false;
    }
}
