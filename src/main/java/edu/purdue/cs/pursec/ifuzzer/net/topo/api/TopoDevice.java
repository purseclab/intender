package edu.purdue.cs.pursec.ifuzzer.net.topo.api;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class TopoDevice extends TopoNode {
    private final TopoType type = TopoType.DEVICE;
    private String name;
    private String mfr;
    private String hwVersion;
    private String swVersion;
    private String chassisId;
    //private Date occurence;


    public TopoDevice(JsonObject jObject) {
        super();
        if (jObject.get("switch_id") != null)
            super.setId(jObject.get("switch_id").getAsString());
        else if (jObject.get("id") != null)
            super.setId(jObject.get("id").getAsString());

        if (jObject.get("infra_device_name") != null)
            name = jObject.get("infra_device_name").getAsString();
        else if (jObject.get("type") != null)
            name = jObject.get("type").getAsString();

        if (jObject.get("mfr") != null)
            mfr = jObject.get("mfr").getAsString();

        if (jObject.get("hw_version") != null)
            hwVersion = jObject.get("hw_version").getAsString();
        else if (jObject.get("hw") != null)
            hwVersion = jObject.get("hw").getAsString();

        if (jObject.get("sw_version") != null)
            swVersion = jObject.get("sw_version").getAsString();
        else if (jObject.get("sw") != null)
            swVersion = jObject.get("sw").getAsString();

        if (jObject.get("chassis_id") != null)
            chassisId = jObject.get("chassis_id").getAsString();
        else if (jObject.get("chassisId") != null)
            chassisId = jObject.get("chassisId").getAsString();

        if (jObject.get("available") != null)
            super.setState(State.of(jObject.get("available").getAsBoolean()));
        else
            super.setState(State.ACTIVE);
    }

    public TopoDevice(String dpid) {
        super.setId(dpid);
    }

    public String getName() {
        return name;
    }

    public String getMfr() {
        return mfr;
    }

    public String getHwVersion() {
        return hwVersion;
    }

    public String getSwVersion() {
        return swVersion;
    }

    public String getChassisId() {
        return chassisId;
    }

    @Override
    public TopoType type() {
        return this.type;
    }

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }

    @Override
    public String getAddr() {
        // TODO
        return "0.0.0.0";
    }

    public static String getId(JsonObject jObject) {
        String id = null;
        if (jObject.has("switch_id"))
            id = jObject.get("switch_id").getAsString();
        else if (jObject.has("id"))
            id = jObject.get("id").getAsString();

        return id;
    }

    public boolean compare(TopoDevice node) {
        if (!super.compare(node))
            return false;

        if (!this.name.equals(node.getName()))
            return false;

        if (!this.mfr.equals(node.getMfr()))
            return false;

        if (!this.chassisId.equals(node.getChassisId()))
            return false;

        if (!this.hwVersion.equals(node.getHwVersion()))
            return false;

        if (!this.swVersion.equals(node.getSwVersion()))
            return false;

        return true;
    }

    @Override
    public JsonObject toJson() {
        JsonObject jObject = new JsonObject();
        jObject.addProperty("id", this.getId());

        return jObject;
    }
}
