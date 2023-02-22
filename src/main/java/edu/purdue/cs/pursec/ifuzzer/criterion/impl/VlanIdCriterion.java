package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;

import java.io.UnsupportedEncodingException;

public class VlanIdCriterion implements Criterion {
    private short vlanId;
    private Type type;

    public VlanIdCriterion(JsonObject jsonObject) throws UnsupportedEncodingException, NumberFormatException {
        String key = "";
        if (jsonObject.has("type")) {
            String typeStr = jsonObject.get("type").getAsString();
            if (typeStr.equals(Type.VLAN_VID.toString())) {
                type = Type.VLAN_VID;
                key = "vlanId";
            } else if (typeStr.equals(Type.INNER_VLAN_VID.toString())) {
                type = Type.INNER_VLAN_VID;
                key = "innerVlanId";
            } else {
                throw new UnsupportedEncodingException();
            }
        }

        if (jsonObject.has(key)) {
            vlanId = (short) (jsonObject.get(key).getAsInt());
        }
    }

    @Override
    public Type type() {
        return this.type;
    }

    public short vlanId() {
        return this.vlanId;
    }
}
