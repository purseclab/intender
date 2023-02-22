package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;

import java.io.UnsupportedEncodingException;

public class IPDscpCriterion implements Criterion {
    private static final byte MASK = 0x3f;
    private byte ipDscp;              // IP DSCP value: 6 bits
    private Type type;

    public IPDscpCriterion(JsonObject jsonObject) throws UnsupportedEncodingException, NumberFormatException {
        if (jsonObject.has("type")) {
            String typeStr = jsonObject.get("type").getAsString();
            if (typeStr.equals(Type.IP_DSCP.toString()))
                type = Type.IP_DSCP;
            else
                throw new UnsupportedEncodingException();
        }

        if (jsonObject.has("ipDscp")) {
            ipDscp = jsonObject.get("ipDscp").getAsByte();
        }
    }

    @Override
    public Type type() {
        return Type.IP_DSCP;
    }

    public short ipDscp() {
        return this.ipDscp;
    }
}
