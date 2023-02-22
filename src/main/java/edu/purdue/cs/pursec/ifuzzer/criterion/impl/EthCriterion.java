package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;
import org.projectfloodlight.openflow.types.MacAddress;

import java.io.UnsupportedEncodingException;

public class EthCriterion implements Criterion {
    private MacAddress mac;
    private MacAddress mask;
    private Type type;

    public EthCriterion(MacAddress mac, MacAddress mask, Type type) {
        this.mac = mac;
        this.mask = mask;
        this.type = type;
    }

    public EthCriterion(MacAddress mac, Type type) {
        this(mac, null, type);
    }

    public EthCriterion(JsonObject jsonObject) throws UnsupportedEncodingException, IllegalArgumentException {
        if (jsonObject.has("type")) {
            String typeStr = jsonObject.get("type").getAsString();
            if (typeStr.equals(Type.ETH_SRC.toString()))
                type = Type.ETH_SRC;
            else if (typeStr.equals(Type.ETH_DST.toString()))
                type = Type.ETH_DST;
            else if (typeStr.equals(Type.ETH_SRC_MASKED.toString()))
                type = Type.ETH_SRC_MASKED;
            else if (typeStr.equals(Type.ETH_DST_MASKED.toString()))
                type = Type.ETH_DST_MASKED;
            else
                throw new UnsupportedEncodingException();
        }

        if (jsonObject.has("mac"))
            this.mac = MacAddress.of(jsonObject.get("mac").getAsString());

        if (jsonObject.has("macMask"))
            this.mask = MacAddress.of(jsonObject.get("macMask").getAsString());
    }

    @Override
    public Type type() {
        return this.type;
    }

    public MacAddress mac() {
        return mac;
    }

    public MacAddress mask() {
        return mask;
    }
}
