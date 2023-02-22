package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;

import java.io.UnsupportedEncodingException;

public class VlanPcpCriterion implements Criterion {
    private static final byte MASK = 0x7;
    private byte vlanPcp;             // VLAN pcp value: 3 bits
    private Type type;

    public VlanPcpCriterion(JsonObject jsonObject) throws UnsupportedEncodingException, NumberFormatException {
        String key = "";
        if (jsonObject.has("type")) {
            String typeStr = jsonObject.get("type").getAsString();
            if (typeStr.equals(Type.VLAN_PCP.toString())) {
                type = Type.VLAN_PCP;
                key = "priority";
            } else if (typeStr.equals(Type.INNER_VLAN_PCP.toString())) {
                type = Type.INNER_VLAN_PCP;
                key = "innerPriority";
            } else {
                throw new UnsupportedEncodingException();
            }
        }

        if (jsonObject.has(key)) {
            vlanPcp = jsonObject.get(key).getAsByte();
        }
    }

    @Override
    public Type type() {
        return this.type;
    }

    public byte vlanPcp() {
        return this.vlanPcp;
    }
}
