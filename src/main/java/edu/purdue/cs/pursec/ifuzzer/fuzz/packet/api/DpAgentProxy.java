package edu.purdue.cs.pursec.ifuzzer.fuzz.packet.api;

import com.google.gson.JsonObject;

public class DpAgentProxy {
    private String mgmt;
    private String iface;

    public DpAgentProxy(String mgmt, String iface) {
        this.mgmt = mgmt;
        this.iface = iface;
    }

    public DpAgentProxy(JsonObject jsonObject) {
        this.mgmt = "";
        if (jsonObject.has("ip"))
            this.mgmt = jsonObject.get("ip").getAsString();
        this.iface = "";
        if (jsonObject.has("iface"))
            this.iface = jsonObject.get("iface").getAsString();
    }

    public String getMgmt() {
        return mgmt;
    }

    public String getIface() {
        return iface;
    }
}
