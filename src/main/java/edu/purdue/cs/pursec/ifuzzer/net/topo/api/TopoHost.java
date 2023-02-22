package edu.purdue.cs.pursec.ifuzzer.net.topo.api;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.projectfloodlight.openflow.types.IPAddress;
import org.projectfloodlight.openflow.types.MacAddress;

import java.util.HashSet;
import java.util.Set;

public class TopoHost extends TopoNode {
    private final TopoType type = TopoType.HOST;
    private MacAddress mac;
    private Set<IPAddress> ips;
    private String vlan;

    public TopoHost(JsonObject jObject, boolean setMacAsId) {
        super();
        super.setState(State.ACTIVE);
        ips = new HashSet<>();

        if (jObject.get("mac") != null)
            this.mac = MacAddress.of(jObject.get("mac").getAsString());


        if (jObject.get("id") != null) {
            super.setId(jObject.get("id").getAsString());
        } else if (setMacAsId) {
            super.setId(this.mac.toString().toUpperCase() + "/None");
        }

        if (jObject.get("ipAddresses") != null) {
            JsonArray jIps = jObject.get("ipAddresses").getAsJsonArray();
            jIps.forEach(k -> ips.add(IPAddress.of(k.getAsString())));
        } else if (jObject.has("ip")) {
            ips.add(IPAddress.of(jObject.get("ip").getAsString()));
        }
    }

    public TopoHost(JsonObject jsonObject) {
        this(jsonObject, false);
    }

    public TopoHost(String ipStr) {
        super();
        ips = new HashSet<>();
        ips.add(IPAddress.of(ipStr));
        mac = MacAddress.NONE;
    }

    public TopoHost(String ipStr, String macAddr) {
        super();
        ips = new HashSet<>();
        ips.add(IPAddress.of(ipStr));
        mac = MacAddress.of(macAddr);
        super.setId(this.mac.toString().toUpperCase() + "/None");
    }

    public MacAddress getMac() {
        return mac;
    }

    public void setMac(String macAddr) {
        this.mac = MacAddress.of(macAddr);
    }

    public Set<IPAddress> getIps() {
        return ips;
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

    public boolean compare(TopoHost host) {
        if (!super.compare(host))
            return false;

        if (!this.mac.equals(host.getMac()))
            return false;

        if (!this.ips.equals(host.ips))
            return false;

        return true;
    }

    @Override
    public String getAddr() {
        // TODO: support multiple address
        for (IPAddress ip : this.ips) {
            return ip.toString();
        }

        return null;
    }

    @Override
    public JsonObject toJson() {
        JsonObject jObject = new JsonObject();
        jObject.addProperty("id", this.getId());

        JsonArray ipJsonArr = new JsonArray();

        for (IPAddress ip : this.ips) {
            ipJsonArr.add(ip.toString());
        }
        jObject.add("ipAddresses", ipJsonArr);
        jObject.addProperty("mac", this.mac.toString());

        return jObject;
    }
}
